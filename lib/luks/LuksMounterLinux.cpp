#include "LuksMounterLinux.h"
#include "LuksVerityMount.h"
#include "core/Compatibility.h"
#include "core/LogMacros.h"

#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <cinttypes>
#include <chrono>
#include <array>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <map>
#include <set>
#include <fstream>

#include <filesystem>
#include <vector>
#include <memory>
#include <string>
#include <string_view>
#include <libcryptsetup.h>
#include <linux/loop.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include "dm-verity/DmVerityUtils.h"
#include <iostream>
#include <uuid/uuid.h>
// keyutils.h on some platforms uses 'private' as a parameter name (C++ keyword)
// example
// include/keyutils.h:221:48: error: expected ',' or '...' before 'private'
//  221 | extern long keyctl_dh_compute_kdf(key_serial_t private, key_serial_t prime,
//      |                                                ^~~~~~~

extern "C" {
#define private private_
#include <keyutils.h>
#undef private
}
// libjose headers have no extern "C" guards of their own
extern "C" {
#include <jose/jose.h>
}
#include <jansson.h>

#if defined(LIBRALF_NS)
using namespace LIBRALF_NS;
#endif

using namespace entos::ralf::dmverity;

// supported filesystems - enough to have erofs for now
static const std::map<ILuksMounter::FileSystemType, const char *> kFileSystemTypeNames = {
    { ILuksMounter::FileSystemType::Erofs, "erofs" },
};

static const char* CACHE_KEY_DESC_PREFIX = "ralf:cached:masterkey:";
static const size_t EXPECTED_KEY_SIZE = 64; // 512 bits for AES-XTS-512

// "logon" keys cannot be read back by userspace; dm-crypt resolves the key
// reference in-kernel (key service), so the payload never leaves the kernel.
static const char* CACHE_KEY_TYPE = "logon";

// Keyring holding the cached master key.
// Session keyring: shared by all processes in the login session, survives process restarts.
//static const key_serial_t CACHE_KEYRING = KEY_SPEC_SESSION_KEYRING;
// Process keyring alternative: private to the calling process, dropped when it exits.
static const key_serial_t CACHE_KEYRING = KEY_SPEC_PROCESS_KEYRING;

// Cache entry description is derived from the wrapped key, so a key cached
// for one wrappedKey is never used for a different one.
static std::string cacheKeyDescFor(const std::vector<uint8_t>& wrappedKey) {
    std::array<uint8_t, SHA256_DIGEST_LENGTH> digest;
    SHA256(wrappedKey.data(), wrappedKey.size(), digest.data());
    return std::string(CACHE_KEY_DESC_PREFIX) + DmVerityUtils::bytesToHexString(digest.data(), digest.size());
}

// Wipe key material from RAM as soon as it is no longer needed.
// Order matters: cleanse while the pages are still mlock'ed, so the wiped
// (not the plaintext) content is what could ever reach swap afterwards.
static void secureWipe(std::vector<uint8_t>& buf) {
    if (!buf.empty()) {
        OPENSSL_cleanse(buf.data(), buf.size());
        munlock(buf.data(), buf.size());
        buf.clear();
    }
}

// RAII guard: while plaintext key material lives in this process, make it
// non-dumpable and disable core files, so a crash cannot write the key to
// disk. PR_SET_DUMPABLE=0 additionally blocks ptrace and /proc/<pid>/mem
// access from same-UID processes. Previous state is restored on destruction.
class CoreDumpGuard {
public:
    CoreDumpGuard() {
        dumpable_ = prctl(PR_GET_DUMPABLE);
        if (dumpable_ != 0) {
            prctl(PR_SET_DUMPABLE, 0);
        }
        if (getrlimit(RLIMIT_CORE, &savedCoreLimit_) == 0) {
            const struct rlimit noCore = {0, 0};
            coreLimitSaved_ = (setrlimit(RLIMIT_CORE, &noCore) == 0);
        }
    }
    ~CoreDumpGuard() {
        if (coreLimitSaved_) {
            setrlimit(RLIMIT_CORE, &savedCoreLimit_);
        }
        if (dumpable_ > 0) {
            prctl(PR_SET_DUMPABLE, dumpable_);
        }
    }
    CoreDumpGuard(const CoreDumpGuard&) = delete;
    CoreDumpGuard& operator=(const CoreDumpGuard&) = delete;
private:
    int dumpable_ = -1;
    struct rlimit savedCoreLimit_ = {};
    bool coreLimitSaved_ = false;
};

bool LuksMounterLinux::isMasterKeyInCache(const std::string& keyDesc) {
    logInfo("Looking up master key in cache: %s", keyDesc.c_str());
    key_serial_t key_id = request_key(CACHE_KEY_TYPE, keyDesc.c_str(), nullptr, CACHE_KEYRING);
    logInfo("Master key cache %s: %s", key_id == -1 ? "miss" : "hit", keyDesc.c_str());
    return key_id != -1;
}

bool LuksMounterLinux::saveMasterKeyToCache(const std::vector<uint8_t>& wrappedKey, const std::vector<uint8_t>& key) {
    const std::string keyDesc = cacheKeyDescFor(wrappedKey);
    logInfo("Saving master key to cache: %s", keyDesc.c_str());
    key_serial_t key_id = add_key(
        CACHE_KEY_TYPE,
        keyDesc.c_str(),
        key.data(),
        key.size(),
        CACHE_KEYRING
    );
    return (key_id != -1);
}

// utility to unwrap the key - now use the static file, jose tool, and wrappedKey value  - require final hardening, but it is a POC
Result<std::vector<uint8_t>> LuksMounterLinux::unwrapKeyMaterial(
    const std::vector<uint8_t>& wrappedKey, 
    const std::filesystem::path& jwkPath) 
{
    auto make_error = []()
    {
        return Result<std::vector<uint8_t>>(); 
    };

    if (wrappedKey.empty())
    {
        return make_error();
    }

    int pipe_in[2];   // write to pipe_in[1] -> jose read from pipe_in[0]
    int pipe_out[2];  // jose write to pipe_out[1] -> C++ read from pipe_out[0]

    //make pipes
    if (pipe(pipe_in) < 0)
    {
        return make_error();
    }
    
    if (pipe(pipe_out) < 0)
    {
        close(pipe_in[0]);
        close(pipe_in[1]);
        return make_error();
    }

    // forking for jose
    pid_t pid = fork();
    if (pid < 0)
    {
        close(pipe_in[0]);  close(pipe_in[1]);
        close(pipe_out[0]); close(pipe_out[1]);
        return make_error();
    }

    if (pid == 0)
    {
        
        // redirect stdin to read from pipe
        if (dup2(pipe_in[0], STDIN_FILENO) < 0) _exit(1);
        
        // redirect stdout) na write to pipe
        if (dup2(pipe_out[1], STDOUT_FILENO) < 0) _exit(1);

        // close not used
        close(pipe_in[0]);  close(pipe_in[1]);
        close(pipe_out[0]); close(pipe_out[1]);

        // launch binary
        execlp("/usr/bin/jose", "jose", "jwe", "dec", "-i-", "-k", jwkPath.c_str(), nullptr);
        _exit(1);
    }

    // close pipes
    close(pipe_in[0]);
    close(pipe_out[1]);

    // write jose token
    size_t total_written = 0;
    bool write_failed = false;
    
    while (total_written < wrappedKey.size())
    {
        ssize_t written = write(pipe_in[1], wrappedKey.data() + total_written, wrappedKey.size() - total_written);
        if (written <= 0)
        {
            write_failed = true;
            break;
        }
        total_written += written;
    }
    
    // close to signal the completeness of the token
    close(pipe_in[1]); 

    if (write_failed)
    {
        close(pipe_out[0]);
        waitpid(pid, nullptr, 0);
        return make_error();
    }

    // read output bin
    std::vector<uint8_t> decryptedBytes;
    char buffer[4096];
    ssize_t bytes_read;
    
    while ((bytes_read = read(pipe_out[0], buffer, sizeof(buffer))) > 0)
    {
        decryptedBytes.insert(decryptedBytes.end(), buffer, buffer + bytes_read);
    }
    close(pipe_out[0]);
    // the stack buffer still holds the tail of the key material
    OPENSSL_cleanse(buffer, sizeof(buffer));

    // Wait for finish
    int status = 0;
    waitpid(pid, &status, 0);

    // Check if finished
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || decryptedBytes.empty())
    {
        secureWipe(decryptedBytes);
        return make_error();
    }

    // return the decrypted bytes
    return Result<std::vector<uint8_t>>(std::move(decryptedBytes));
}

using CryptDevicePtr = std::unique_ptr<struct crypt_device, void(*)(struct crypt_device*)>;

// crypt_init + crypt_load: LUKS2 header parsing (libcryptsetup is used only for this)
static Result<CryptDevicePtr> initAndLoadLuksDevice(const std::string& loopDevPath)
{
    struct crypt_device *cd = nullptr;
    // initialization of libcrypt for pointed loopback
    int r = crypt_init(&cd, loopDevPath.c_str());
    if (r < 0)
    {
        logError("libcryptsetup: Failed to init device for %s (code: %d)", loopDevPath.c_str(), r);
        return Error::format(ErrorCode::DmVerityError, "libcryptsetup: Failed to init device for %s (code: %d)", loopDevPath.c_str(), r);
    }
    logInfo("luksActivate: crypt_init: ok on: %s", loopDevPath.c_str());

    // safe smart pointer to release the memory after crypt_init
    CryptDevicePtr cdPtr(cd, [](struct crypt_device* c)
    {
        if (c) crypt_free(c);
    });

    // Parse and load LUKS header and metadata
    r = crypt_load(cd, CRYPT_LUKS2, nullptr);
    if (r < 0)
    {
        logError("libcryptsetup: Device %s is not a compliant LUKS2 container (code: %d)", loopDevPath.c_str(), r);
        return Error::format(ErrorCode::DmVerityError, "libcryptsetup: Device %s is not a compliant LUKS2 container (code: %d)", loopDevPath.c_str(), r);
    }
    logInfo("luksActivate: crypt_load: ok");

    return Result<CryptDevicePtr>(std::move(cdPtr));
}

static bool getDeviceOrFileSize(int fd, uint64_t &size);

// Activate the LUKS volume with dm-crypt referencing the volume key from the
// kernel keyring (key service ":<size>:<type>:<description>") - the kernel
// resolves the key itself, so the payload never enters this process at all.
// libcryptsetup is used only to parse the LUKS2 header.
// Returns the device node of the decrypted dm-crypt device.
Result<std::filesystem::path> LuksMounterLinux::luksActivateFromKeyring(const std::string& loopDevPath,
                                                       const std::string& luksVolumeName,
                                                       const std::string& keyDesc,
                                                       bool useUDevSync)
{
    logInfo("luksActivateFromKeyring looper: %s volume: %s key: %s", loopDevPath.c_str(), luksVolumeName.c_str(), keyDesc.c_str());

    auto cdPtrResult = initAndLoadLuksDevice(loopDevPath);
    if (!cdPtrResult)
    {
        return cdPtrResult.error();
    }
    struct crypt_device *cd = cdPtrResult.value().get();

    // Read the LUKS2 segment/cipher parameters needed to build the dm-crypt table
    const char* cipher = crypt_get_cipher(cd);
    const char* cipherMode = crypt_get_cipher_mode(cd);
    const int keySize = crypt_get_volume_key_size(cd);
    const int sectorSize = crypt_get_sector_size(cd);
    if (!cipher || !cipherMode || keySize <= 0 || sectorSize <= 0)
    {
        return Error::format(ErrorCode::DmVerityError, "libcryptsetup: Failed to read cipher info for %s", loopDevPath.c_str());
    }
    const std::string cipherSpec = std::string(cipher) + "-" + cipherMode;
    const uint64_t dataOffset = crypt_get_data_offset(cd); // in 512-byte sectors
    const uint64_t ivOffset = crypt_get_iv_offset(cd);

    logInfo("LUKS geometry: cipher=%s mode=%s keySize=%dB sectorSize=%dB dataOffset=%" PRIu64 " (512B sectors) ivOffset=%" PRIu64,
            cipher, cipherMode, keySize, sectorSize, dataOffset, ivOffset);

    // Size of the whole underlying device - the mapped area starts after the LUKS header
    int loopFd = open(loopDevPath.c_str(), O_RDONLY | O_CLOEXEC);
    if (loopFd < 0)
    {
        return Error::format(std::error_code(errno, std::system_category()), "Failed to open %s", loopDevPath.c_str());
    }
    uint64_t deviceSize = 0;
    const bool sizeOk = getDeviceOrFileSize(loopFd, deviceSize);
    close(loopFd);
    if (!sizeOk)
    {
        return Error::format(ErrorCode::DmVerityError, "Failed to get size of %s", loopDevPath.c_str());
    }
    logInfo("LUKS geometry: device=%s deviceSize=%" PRIu64 " B (%" PRIu64 " sectors) mappedSize=%" PRIu64 " B",
            loopDevPath.c_str(), deviceSize, deviceSize / 512, deviceSize - dataOffset * 512);

    DevMapper devMapper;
    auto mappedPath = devMapper.mapWithCrypt(loopDevPath, luksVolumeName, "", deviceSize, cipherSpec,
                                             CACHE_KEY_TYPE, keyDesc, static_cast<size_t>(keySize),
                                             ivOffset, dataOffset, static_cast<uint32_t>(sectorSize), useUDevSync);
    if (!mappedPath)
    {
        return mappedPath.error();
    }
    logInfo("luksActivateFromKeyring: ok on: %s (%s)", luksVolumeName.c_str(), mappedPath.value().c_str());

    return mappedPath;
}

static std::string generateUUID() {
    uuid_t binuuid;
    uuid_generate_random(binuuid);
    char uuid_str[37];
    uuid_unparse_lower(binuuid, uuid_str);
    return std::string(uuid_str);
}

static bool getDeviceOrFileSize(int fd, uint64_t &size) {
    struct stat fileStat;
    if (fstat(fd, &fileStat) < 0) {
        return false;
    }

    // Check if we have block device
    if (S_ISBLK(fileStat.st_mode)) {
        uint64_t bytes = 0;
        // ioctl BLKGETSIZE64 get size of the block device
        if (::ioctl(fd, BLKGETSIZE64, &bytes) < 0) {
            return false;
        }
        size = bytes;
        return true;
    }

    // ordinary file case fileStat.st_size
    size = static_cast<uint64_t>(fileStat.st_size);
    return true;
}

Result<std::unique_ptr<IPackageMountImpl>> 
LuksMounterLinux::doMount(std::string_view name, FileSystemType fsType, int imageFd,
                          const std::filesystem::path &mountPoint, FileRange luksRange, FileRange hashRange,
                          const std::vector<uint8_t> &rootHash,
                          const std::vector<uint8_t> &wrappedKey, MountFlags flags)
{
    // Sanity check: make sure mountpoint is the existing directory
    std::error_code err;
    auto status = std::filesystem::symlink_status(mountPoint, err);
    if (status.type() != std::filesystem::file_type::directory)
    {
        logError("Mount point '%s' is not a directory", mountPoint.c_str());
        return Error::format(ErrorCode::InvalidArgument, "Mount point '%s' is not a directory", mountPoint.c_str());
    }

    auto startTime = std::chrono::steady_clock::now();
    // attach looper device for full LUKS image including headers of LUKS
    auto loopDevFd = DmVerityUtils::loopDeviceAttach(imageFd, luksRange, flags);
    if (!loopDevFd) return loopDevFd.error();
    logInfo("Looper device attached to LUKS data blob");

    struct loop_info64 info = {};
    std::string loopDevPath;

    // loopDevFd.value() is just descriptor number, ask for lo_number.
    if (::ioctl(loopDevFd.value(), LOOP_GET_STATUS64, &info) == 0)
    {
        // create correct path
        loopDevPath = "/dev/loop" + std::to_string(info.lo_number);
    } 
    else
    {
        logError("LUKS Mounter: Failed to get loop device status via ioctl");
        err = std::error_code(errno, std::system_category());
        ::close(loopDevFd.value());
        return Error::format(err, "LUKS Mounter: Failed to get loop device status via ioctl");
    }
    logInfo("Looper device path for LUKS: %s", loopDevPath.c_str());

    auto startTimeUnwrap = std::chrono::steady_clock::now();
    // Unwrap the key - assume hardcoded location of /media/mass_storage/recipient_private.jwk
    std::string dynamicPath = "/media/mass_storage/recipient_private.jwk";
    std::string fallbackPath = "/home/mikolaj.staworzynski/projects/LGI/BOLT_ENCRYPTION/master_key_build/example/intermediate_files/recipient_private.jwk";
    std::string chosenPath = std::filesystem::exists(dynamicPath) ? dynamicPath : fallbackPath;
    const std::string keyDesc = cacheKeyDescFor(wrappedKey);
    // The volume is activated with the key referenced from the kernel keyring
    // (dm-crypt key service) - the key payload never enters this process.
    std::vector<uint8_t> unwrappedKey;
    {
        // Plaintext key material lives in this process only within this scope:
        // core dumps and same-UID ptrace//proc inspection stay disabled until
        // the guard is destroyed, i.e. strictly after secureWipe() below.
        CoreDumpGuard coreGuard;

        const bool keyInCache = isMasterKeyInCache(keyDesc);
        if (!keyInCache)
        {
            logInfo("Master key not found in cache, unwrapping from JWK");
            auto unwrapResult = unwrapKeyMaterial(wrappedKey, chosenPath);
            if (!unwrapResult)
            {
                logError("Failed to unwrap AES key material via jose CLI");
                close(loopDevFd.value());
                return unwrapResult.error();
            }
            unwrappedKey = std::move(unwrapResult.value());
            if (unwrappedKey.size() != EXPECTED_KEY_SIZE)
            {
                logError("Unwrapped key size is incorrect: expected %zu bytes, got %zu bytes", EXPECTED_KEY_SIZE, unwrappedKey.size());
                secureWipe(unwrappedKey);
                close(loopDevFd.value());
                return Error(ErrorCode::DmVerityError, "Unwrapped key size is incorrect");
            }
            // Save the unwrapped key to cache for future use
            if (!saveMasterKeyToCache(wrappedKey, unwrappedKey))
            {
                logWarning("Failed to save master key to cache");
            }
            else
            {
                logInfo("Master key saved to cache");
            }
        }
        else
        {
            logInfo("Master key found in cache (stays in kernel keyring)");
        }
        auto endTimeUnwrap = std::chrono::steady_clock::now();
        auto durationMsUnwrap = std::chrono::duration<double, std::milli>(endTimeUnwrap - startTimeUnwrap).count();
        printf("PERF: Key unwrap/get took %.2f ms\n", durationMsUnwrap);

        // The kernel resolves the key from the keyring by itself - the RAM copy
        // (only present right after a fresh unwrap) can go before the activation.
        secureWipe(unwrappedKey);
    }

    // LUKS container activation
    std::string randomUuid = generateUUID();
    std::string luksVolumeName = std::string(name) + "_" + randomUuid + "_crypt";
    logInfo("LUKS volume name: %s", luksVolumeName.c_str());

    auto luksResult = luksActivateFromKeyring(loopDevPath, luksVolumeName, keyDesc,
                                              (flags & MountFlag::UDevSync) == MountFlag::UDevSync);

    // We could close looper, kernel holds the mapping
    if (close(loopDevFd.value()) != 0)
    {
        logSysError(errno, "failed to close loop device");
    }

    if (!luksResult)
    {
        logError("Failed to mount LUKS");
        return luksResult.error();
    }
    // Use the device node found by the devmapper - nothing guarantees /dev/mapper/<name> exists
    const std::string luksMappedPath = luksResult.value().string();
    logInfo("LUKS volume mounted in: %s (%s)", luksVolumeName.c_str(), luksMappedPath.c_str());
    auto endTime = std::chrono::steady_clock::now();
    auto durationMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
    printf("PERF: LUKS part (with unwrap) took %.2f ms\n", durationMs);

    startTime = std::chrono::steady_clock::now();
    // Open unencrypted device and prepare verity
    int decryptedFd = open(luksMappedPath.c_str(), O_RDONLY);
    if (decryptedFd < 0)
    {
        logError("Failed to open decrypted LUKS device");
        crypt_deactivate(nullptr, luksVolumeName.c_str());
        return Error::format(std::error_code(errno, std::system_category()), "Failed to open decrypted LUKS device");
    }

    uint64_t decryptedTotalSize = 0;
    if (!getDeviceOrFileSize(decryptedFd, decryptedTotalSize))
    {
        logError("Failed to get size of decrypted LUKS volume");
        close(decryptedFd);
        crypt_deactivate(nullptr, luksVolumeName.c_str());
        return Error(ErrorCode::DmVerityError, "Failed to get size of decrypted LUKS volume");
    }

    // Calculate relative offsets, we have already only the decrypted payload of LUKS
    const uint64_t verityHashesOffset = hashRange.offset; 
    const uint64_t actualDataSize = verityHashesOffset; 
    const uint64_t actualHashesSize = decryptedTotalSize - verityHashesOffset;
    logInfo("Total LUKS size: %" PRIu64 "", decryptedTotalSize);
    logInfo("Total data: %" PRIu64 "", actualDataSize);
    logInfo("Hash offset: %" PRIu64 "", verityHashesOffset);
    logInfo("Hash size: %" PRIu64 "", actualHashesSize);

    // Read and veiry dm-verity superblock from the mounted LUKS
    const auto sb = DmVerityUtils::readDmVeritySuperBlock(decryptedFd, {0, actualDataSize}, {verityHashesOffset, actualHashesSize});
    if (!sb)
    {
        close(decryptedFd);
        crypt_deactivate(nullptr, luksVolumeName.c_str());
        return sb.error();
    }
    logInfo("VERITY internally validated");

    // Configure endpoint in Device Mapperze
    DevMapper devMapper;
    if (!devMapper.isAvailable())
    {
        logError("Device mapper is not available on this system");
        close(decryptedFd);
        crypt_deactivate(nullptr, luksVolumeName.c_str());
        return Error(ErrorCode::DmVerityError, "Device mapper is not available on this system");
    }

    // create device mapper device name and uuid - like in erofs+dmverity path
    auto volumeNameAndUuid = DmVerityUtils::createDeviceNameAndUuid(devMapper, name, sb->uuid);
    if (!volumeNameAndUuid)
    {
        close(decryptedFd);
        crypt_deactivate(nullptr, luksVolumeName.c_str());
        return volumeNameAndUuid.error();
    }

    const auto volumeName = std::move(volumeNameAndUuid->first);
    const auto volumeUuid = std::move(volumeNameAndUuid->second);

    logInfo("Volume name %s uuid %s", volumeName.c_str(), volumeUuid.c_str());


    // Mounting verity
    int luksFd = open(luksMappedPath.c_str(), O_RDONLY);
    if (luksFd < 0)
    {
        logError("Failed to re-open LUKS device for verity mapping");
        close(decryptedFd);
        crypt_deactivate(nullptr, luksVolumeName.c_str());
        return Error::format(std::error_code(errno, std::system_category()), "Failed to re-open LUKS device for verity mapping");
    }
    close(decryptedFd);

    // Verity
    auto mapperDevPath = devMapper.mapWithVerity(
        luksFd, 
        volumeName, 
        volumeUuid,
        verityHashesOffset, 
        actualDataSize, // that is the size of the data partition
        rootHash, 
        (flags & MountFlag::UDevSync) == MountFlag::UDevSync
    );

    close(luksFd);

    if (!mapperDevPath)
    {
        logError("Failed to map verity");
        crypt_deactivate(nullptr, luksVolumeName.c_str());
        return mapperDevPath.error();
    }
    endTime = std::chrono::steady_clock::now();
    durationMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
    printf("PERF: VERITY part took %.2f ms\n", durationMs);

    startTime = std::chrono::steady_clock::now();
    // Erofs mounting
    unsigned long mountFlags = MS_RDONLY; // bolt filesystem partition is read only
    if ((flags & MountFlag::NoDevice) == MountFlag::NoDevice) mountFlags |= MS_NODEV;
    if ((flags & MountFlag::NoSuid) == MountFlag::NoSuid)     mountFlags |= MS_NOSUID;
    if ((flags & MountFlag::NoExec) == MountFlag::NoExec)     mountFlags |= MS_NOEXEC;

    logInfo("Mounting erofs mapper: %s, mountpoint: %s", mapperDevPath->c_str(), mountPoint.c_str());
    if (::mount(mapperDevPath->c_str(), mountPoint.c_str(), kFileSystemTypeNames.at(fsType), mountFlags, nullptr) != 0)
    {
        logError("Failed to mount LUKS+Verity image '%s' at '%s'", mapperDevPath->c_str(), mountPoint.c_str());
        err = std::error_code(errno, std::system_category());
        devMapper.unmap(volumeName, volumeUuid, false);
        crypt_deactivate(nullptr, luksVolumeName.c_str());
        return Error::format(err, "Failed to mount LUKS+Verity image '%s' at '%s'", mapperDevPath->c_str(), mountPoint.c_str());
    }

    // Check status of the device
    auto dmStatus = devMapper.mapStatus(volumeName, volumeUuid);
    if (!dmStatus || dmStatus.value().empty() || dmStatus.value().rfind("V", 0) != 0)
    {
        logError("Detected corruption in crypt-verity image block layout");
        ::umount2(mountPoint.c_str(), MNT_FORCE);
        devMapper.unmap(volumeName, volumeUuid, false);
        crypt_deactivate(nullptr, luksVolumeName.c_str());
        
        if (!dmStatus) return dmStatus.error();
        else return Error(ErrorCode::DmVerityError, "Detected corruption in crypt-verity image block layout");
    }

    bool autoClear = false;
    if ((flags & MountFlag::NoAutoClear) != MountFlag::NoAutoClear)
    {
        autoClear = true;
        logInfo("Arming kernel for deferred cleanup of device mapper stack...");

        // Mark DM-Verity to defferred remove
        // When rootfs become unmounted, mapping would be removed
        if (!devMapper.unmap(volumeName, volumeUuid, true)) // true = deferred
        {
            logError("Failed to arm deferred unmap for DM-Verity volume: %s", volumeName.c_str());
            autoClear = false;
        }
        else
        {
            logInfo("Deferred unmap armed for DM-Verity: %s", volumeName.c_str());
        }

        if (autoClear)
        {
            // Mark the dm-crypt (LUKS) device for deferred removal too - it is held
            // open by the verity device on top, so it disappears automatically
            // once the verity mapping above it is gone.  Done via devmapper
            // directly: the device was not created by cryptsetup, so
            // crypt_init_by_name/crypt_deactivate_by_name cannot be used on it.
            if (!devMapper.unmap(luksVolumeName, "", true)) // true = deferred
            {
                logError("Failed to arm deferred unmap for LUKS volume: %s", luksVolumeName.c_str());
                autoClear = false;
            }
            else
            {
                logInfo("Deferred unmap armed for LUKS: %s", luksVolumeName.c_str());
            }
        }
    }

    endTime = std::chrono::steady_clock::now();
    durationMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
    printf("PERF: EROFS part took %.2f ms\n", durationMs);

    // Return object that manage the mountpoint to unmount 
    return std::make_unique<LuksVerityMount>(
        mapperDevPath.value(), 
        mountPoint, 
        volumeName, 
        volumeUuid, 
        luksVolumeName,
        autoClear
    );
}

Result<std::unique_ptr<IPackageMountImpl>>
LuksMounterLinux::mount(std::string_view name, FileSystemType fsType, int imageFd,
                        const std::filesystem::path &mountPoint, FileRange luksRange, FileRange hashRange,
                        const std::vector<uint8_t> &rootHash, const std::vector<uint8_t> &salt,
                        const std::string &keyMaterial, MountFlags flags) const
{
    if (keyMaterial.empty())
    {
        logError("empty wrapped key");
        return Error(ErrorCode::PackageMountInvalid, "LUKS2 Mounter: Encrypted image is missing required JWE key material");
    }

    auto checkResult = checkImageFile(fsType, imageFd, luksRange);
    if (!checkResult)
    {
        logError("checking LUKS2 image failed");
        return checkResult.error();
    }

    std::vector<uint8_t> wrappedKey(keyMaterial.begin(), keyMaterial.end());

    return const_cast<LuksMounterLinux*>(this)->doMount(
        name,
        fsType,
        imageFd,
        mountPoint,
        luksRange,
        hashRange,
        rootHash,
        wrappedKey,
        flags
    );
}

Result<> LuksMounterLinux::checkImageFile(FileSystemType fsType, int imageFd,
                                          FileRange luksRange) const
{
    return Ok();
}
