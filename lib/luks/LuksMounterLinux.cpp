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
#include <cinttypes>
#include <chrono>
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
#include "dm-verity/DmVerityUtils.h"
#include <iostream>
#include <uuid/uuid.h>

#if defined(LIBRALF_NS)
using namespace LIBRALF_NS;
#endif

using namespace entos::ralf::dmverity;

// supported filesystems - enough to have erofs for now
static const std::map<ILuksMounter::FileSystemType, const char *> kFileSystemTypeNames = {
    { ILuksMounter::FileSystemType::Erofs, "erofs" },
};

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

    // Wait for finish
    int status = 0;
    waitpid(pid, &status, 0);

    // Check if finished
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || decryptedBytes.empty())
    {
        return make_error();
    }

    // return the decrypted bytes
    return Result<std::vector<uint8_t>>(std::move(decryptedBytes));
}

Result<void> LuksMounterLinux::luksActivate(const std::string& loopDevPath, 
                                            const std::string& luksVolumeName, 
                                            const std::vector<uint8_t>& raw512BitKey)
{
    logInfo("luksActivate looper: %s volume: %s keySizeInBytes: %ld", loopDevPath.c_str(), luksVolumeName.c_str(), raw512BitKey.size());

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
    std::unique_ptr<struct crypt_device, void(*)(struct crypt_device*)> cdPtr(cd, [](struct crypt_device* c)
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

    // Activate block device with 512bits passphrase
    // set CRYPT_ACTIVATE_READONLY, to grant lack of modification of OCI files
    //r = crypt_activate_by_passphrase(cd, luksVolumeName.c_str(), CRYPT_ANY_SLOT, 
    //                                 reinterpret_cast<const char*>(raw512BitKey.data()), 
    //                                 raw512BitKey.size(), CRYPT_ACTIVATE_READONLY);
    r = crypt_activate_by_volume_key(cd, luksVolumeName.c_str(), reinterpret_cast<const char*>(raw512BitKey.data()), 
                                     raw512BitKey.size(), CRYPT_ACTIVATE_READONLY);
    if (r < 0)
    {
        logError("libcryptsetup: Cryptographic authentication failed for %s. Invalid key material (code: %d)", luksVolumeName.c_str(), r);
        return Error::format(ErrorCode::DmVerityError, "libcryptsetup: Cryptographic authentication failed for %s. Invalid key material (code: %d)", luksVolumeName.c_str(), r);
    }
    logInfo("luksActivate: crypt_activate_by_passphrase: ok on: %s", luksVolumeName.c_str());

    return Ok();
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
    logInfo("jwk private to unwrap the key: %s", chosenPath.c_str());
    auto unwrapResult = unwrapKeyMaterial(wrappedKey, chosenPath);
    if (unwrapResult.value().empty())
    {
        logError("Failed to unwrap AES key material via jose CLI");
        close(loopDevFd.value());
        return Error(ErrorCode::DmVerityError, "Failed to unwrap AES key material via jose CLI");
    }
    logInfo("Key unwrapped in RAM");
    auto endTimeUnwrap = std::chrono::steady_clock::now();
    auto durationMsUnwrap = std::chrono::duration<double, std::milli>(endTimeUnwrap - startTimeUnwrap).count();
    printf("PERF: Key unwrap took %.2f ms\n", durationMsUnwrap);

    // LUKS container activation
    std::string randomUuid = generateUUID();
    std::string luksVolumeName = std::string(name) + "_" + randomUuid + "_crypt";
    logInfo("LUKS volume name: %s", luksVolumeName.c_str());
    auto luksResult = luksActivate(loopDevPath, luksVolumeName, unwrapResult.value());

    // Cleanup key value in RAM
    OPENSSL_cleanse(unwrapResult.value().data(), unwrapResult.value().size());
    unwrapResult.value().clear();
    logInfo("Key clean in RAM");

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
    logInfo("LUKS volume mounted in: %s", luksVolumeName.c_str());
    auto endTime = std::chrono::steady_clock::now();
    auto durationMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
    printf("PERF: LUKS part (with unwrap) took %.2f ms\n", durationMs);

    startTime = std::chrono::steady_clock::now();
    // Open unencrypted device and prepare verity
    std::string luksMappedPath = "/dev/mapper/" + luksVolumeName;
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
    if (!dmStatus || (dmStatus.value() != "V"))
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
            struct crypt_device *cd = nullptr;
            if (crypt_init_by_name(&cd, luksVolumeName.c_str()) == 0)
            {
                if (crypt_deactivate_by_name(cd, luksVolumeName.c_str(), CRYPT_DEACTIVATE_DEFERRED) != 0)
                {
                    autoClear = false;
                }
                else 
                {
                    logInfo("Deferred unmap armed for LUKS: %s", luksVolumeName.c_str());
                }
                crypt_free(cd);
           }
           else
           {
                autoClear = false;
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
