#include "DmVerityUtils.h"
#include <set>
#include "core/LogMacros.h"
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <openssl/sha.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/loop.h>
#include <cstring>
#include "IDmVerityMounter.h"


#define ROUND_UP(n, s) ((((n) + (s) - 1) / (s)) * (s))
#define DIV_ROUND_UP(n, d) (((n) + ((d) - 1)) / (d))

namespace entos::ralf::dmverity {

// -----------------------------------------------------------------------------
/*!
    \static
    \internal

    Converts a byte array \a bytes or \a length to a lower case hex string.

 */
std::string DmVerityUtils::bytesToHexString(const uint8_t *bytes, size_t length)
{
    static const char hexChars[17] = "0123456789abcdef";

    std::string str;
    str.reserve(length * 2 + 1);

    for (size_t i = 0; i < length; i++)
    {
        str.push_back(hexChars[((bytes[i] >> 4) & 0xf)]);
        str.push_back(hexChars[((bytes[i] >> 0) & 0xf)]);
    }

    return str;
}

// -----------------------------------------------------------------------------
/*!
    \static
    \internal

    Creates a unique device name and UUID string for the dm-verity device. The
    name is prefixed with "ralf--" followed by the \a id, which is the
    package ID, and a random set of characters to ensure uniqueness. The UUID
    is similar but also includes the \a uuid bytes converted to a hex string.

    A UUID is not strictly required for dm-verity, but I've included it to match
    the behaviour of the cryptsetup utility which creates a UUID.

    The function checks the existing mapped devices in the DevMapper to ensure
    that the generated name and UUID are unique.  It is racy in that some other
    process could create a device with the same name or UUID after this function
    has returned, but that is unlikely to happen in practice.

 */
Result<std::pair<std::string, std::string>> DmVerityUtils::createDeviceNameAndUuid(const DevMapper &devMapper,
                                                                           std::string_view id, const uint8_t uuid[16])
{
    // Get a list of current devices to ensure we can create a unique name and uuid
    auto existingDevices = devMapper.mappedDevices();
    if (!existingDevices)
        return existingDevices.error();

    auto existingDeviceNames = std::set<std::string>();
    for (const auto &device : existingDevices.value())
    {
        logInfo("Found existing devmapper device %u:%u with name '%s'", major(device.deviceNumber),
                minor(device.deviceNumber), device.name.c_str());

        existingDeviceNames.insert(device.name);
    }

    static const char *letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    timeval tv = {};
    gettimeofday(&tv, nullptr);
    uint64_t value = ((uint64_t)tv.tv_usec << 16) ^ tv.tv_sec;

    char volumeName[128];
    char volumeUuid[128];

    const std::string uuidStr = bytesToHexString(uuid, 16);

    const char *idStr = id.data();
    int idLength = static_cast<int>(std::min<size_t>(id.length(), 64));

    for (int attempts = 0; attempts < 100; attempts++, value += 7777)
    {
        char randomChars[7];
        randomChars[0] = letters[value % 62];
        value /= 62;
        randomChars[1] = letters[value % 62];
        value /= 62;
        randomChars[2] = letters[value % 62];
        value /= 62;
        randomChars[3] = letters[value % 62];
        value /= 62;
        randomChars[4] = letters[value % 62];
        value /= 62;
        randomChars[5] = letters[value % 62];
        randomChars[6] = '\0';

        snprintf(volumeName, sizeof(volumeName), "ralf--%.*s--%s", idLength, idStr, randomChars);
        snprintf(volumeUuid, sizeof(volumeUuid), "ralf-%s-%.*s-%s", uuidStr.c_str(), idLength, idStr, randomChars);

        if (existingDeviceNames.count(volumeName) == 0)
            return std::make_pair<std::string, std::string>(volumeName, volumeUuid);
    }

    return Error(ErrorCode::DmVerityError, "Failed to create unique device name and/or uuid after 100 attempts");
}

// -----------------------------------------------------------------------------
/**
    \internal
    \static

    Simply created the path `/proc/self/fd/<fd>`.

 */
std::filesystem::path DmVerityUtils::procPathToFd(int fd)
{
    return std::filesystem::path("/proc/self/fd") / std::to_string(fd);
}

// -----------------------------------------------------------------------------
/**
    \internal
    \static

    Given a number of \a dataBlocks of size \a blockSize the function calculates
    the number hash blocks required in the dm-verity merkle hash tree.

    Assumes a sha256 hash algo.

 */
size_t DmVerityUtils::calcRequiredHashBlocks(size_t dataBlocks, size_t blockSize)
{
    // Special case if a single data block, in which case the root hash stored in the header is just the hash of the
    // single data block, so no hash blocks
    if (dataBlocks == 1)
        return 0;

    const size_t hashesPerBlock = blockSize / SHA256_DIGEST_LENGTH;

    size_t layerHashBlocks = DIV_ROUND_UP(dataBlocks, hashesPerBlock);
    size_t requiredHashBlocks = layerHashBlocks;
    while (layerHashBlocks > 1)
    {
        layerHashBlocks = DIV_ROUND_UP(layerHashBlocks, hashesPerBlock);
        requiredHashBlocks += layerHashBlocks;
    }

    return requiredHashBlocks;
}

// -----------------------------------------------------------------------------
/*!
    \static
    \internal

    Finds a free loop device, returning a path to it's dev node.

 */
Result<std::filesystem::path> DmVerityUtils::getFreeLoopDevice()
{
    int loopControlFd = open("/dev/loop-control", O_RDONLY | O_CLOEXEC);
    if (loopControlFd < 0)
        return Error(std::error_code(errno, std::system_category()), "Failed to open loop-control dev node");

    int rc = ioctl(loopControlFd, LOOP_CTL_GET_FREE);
    if (rc < 0)
    {
        auto err = std::error_code(errno, std::system_category());

        close(loopControlFd);
        return Error(err, "Failed to get available free loop device");
    }

    close(loopControlFd);

    char pathBuf[64];
    snprintf(pathBuf, sizeof(pathBuf), "/dev/loop%d", rc);
    std::filesystem::path loopDevPath = pathBuf;

    struct stat buf = {};
    if ((stat(loopDevPath.c_str(), &buf) != 0) || !S_ISBLK(buf.st_mode))
    {
        return Error::format(std::error_code(errno, std::system_category()), "Failed to access loop device at '%s'",
                             loopDevPath.c_str());
    }

    return loopDevPath;
}

// -----------------------------------------------------------------------------
/*!
    \static
    \internal

    Attempts to attach the supplied image file fd to new loop block device. On
    success an fd to the new /dev/loopX device is returned, on failed \c -1 is
    returned.

 */
Result<int> DmVerityUtils::loopDeviceAttach(int imageFd, IDmVerityMounter::FileRange fileRange, MountFlags flags)
{
    // Loop device creation is racey with respect to other processes also creating loop devices, hence the retry loop
    int loopDevFd = -1;
    std::filesystem::path loopDevPath;
    while (loopDevFd < 0)
    {
        auto loopDevicePath = getFreeLoopDevice();
        if (!loopDevicePath)
        {
            return loopDevicePath.error();
        }

        int openFlags = O_CLOEXEC;
        if ((flags & MountFlag::ReadOnly) == MountFlag::ReadOnly)
            openFlags |= O_RDONLY;
        else
            openFlags |= O_RDWR;

        loopDevPath = loopDevicePath.value();
        loopDevFd = open(loopDevPath.c_str(), openFlags);
        if (loopDevFd < 0)
        {
            return Error::format(std::error_code(errno, std::system_category()), "Failed to open loop device at '%s'",
                                 loopDevPath.c_str());
        }

        if (ioctl(loopDevFd, LOOP_SET_FD, imageFd) < 0)
        {
            const int err = errno;
            close(loopDevFd);
            loopDevFd = -1;

            loopDevPath.clear();

            // if errno is EBUSY then it means someone got there before us and claimed the loop device, so go back
            // around again and try and find another free device
            if (err != EBUSY)
            {
                return Error::format(std::error_code(errno, std::system_category()),
                                     "LOOP_SET_FD ioctl failed on @ '%s'", loopDevPath.c_str());
            }
        }
    }

    loop_info64 info = {};
    memset(&info, 0x00, sizeof(info));

    // We always set autoclear, even if the caller didn't request it, because we always want the loop device to be
    // cleared when the devmapper device is removed.  The MountFlag::AutoClear is used to indicate at the devmapper
    // level to remove the mapping when the device is unmounted.
    info.lo_flags |= LO_FLAGS_AUTOCLEAR;

    // LO_FLAGS_READ_ONLY is not set because apparently this is controlled by open type of the loop device fd

    // Use realpath on the /proc/self/fd/X symlink for the name, the name is just for reference, it's not actually used
    // by the loop device driver
    const std::filesystem::path procPath = procPathToFd(imageFd);
    char *imagePath = realpath(procPath.c_str(), nullptr);
    if (imagePath)
    {
        strncpy(reinterpret_cast<char *>(info.lo_file_name), imagePath, LO_NAME_SIZE - 1);
        free(imagePath);
    }

    // Set the file range we want in the loop back mount
    info.lo_offset = fileRange.offset;
    info.lo_sizelimit = fileRange.size;

    // Apply the loop settings
    if (ioctl(loopDevFd, LOOP_SET_STATUS64, &info) < 0)
    {
        auto err = std::error_code(errno, std::system_category());

        // clear the fd since we've failed
        (void)ioctl(loopDevFd, LOOP_CLR_FD, 0);
        close(loopDevFd);

        return Error::format(err, "Failed to set the loopdevice flags on @ '%s'", loopDevPath.c_str());
    }

    // Set the directio flag
    if ((flags & MountFlag::DirectIO) == MountFlag::DirectIO)
    {
        unsigned long enable = 1;
        if (ioctl(loopDevFd, LOOP_SET_DIRECT_IO, enable) < 0)
        {
            auto err = std::error_code(errno, std::system_category());

            // clear the fd since we've failed
            (void)ioctl(loopDevFd, LOOP_CLR_FD, 0);
            close(loopDevFd);

            return Error::format(err, "Failed to set the loopdevice directio flag on @ '%s'", loopDevPath.c_str());
        }
    }

    return loopDevFd;
}

// -----------------------------------------------------------------------------
/*!
    \static
    \internal

    Reads and sanity checks the dmverity superblock from the given \a imageFileFd
    at the given \a offset.

 */
Result<VeritySuperBlock> DmVerityUtils::readDmVeritySuperBlock(int imageFileFd, IDmVerityMounter::FileRange dataRange,
                                                       IDmVerityMounter::FileRange hashesRange)
{
    constexpr uint64_t blockSize = 4096;

    if (hashesRange.size < blockSize)
        return Error(ErrorCode::DmVerityError, "dmverity hashes range is smaller than superblock size");

    // If O_DIRECT was used to open the image file then all reads need to block aligned, hence the allocation of
    // memaligned buffer
    std::unique_ptr<uint8_t, decltype(std::free) *> alignedBuf(reinterpret_cast<uint8_t *>(
                                                                   std::aligned_alloc(4096, blockSize)),
                                                               std::free);

    // Read the super block
    const ssize_t rd = TEMP_FAILURE_RETRY(pread(imageFileFd, alignedBuf.get(), blockSize, hashesRange.offset));
    if (rd != blockSize)
        return Error(std::error_code(errno, std::system_category()), "Failed to read image file");

    // Sanity check the superblock fields
    const auto *superBlock = reinterpret_cast<const VeritySuperBlock *>(alignedBuf.get());
    auto checkResult = checkSuperBlock(superBlock);
    if (!checkResult)
        return checkResult.error();

    // Check that the dmverity data blocks fit within the data file range
    if ((superBlock->dataBlocks * superBlock->dataBlockSize) > dataRange.size)
    {
        return Error::format(ErrorCode::DmVerityError,
                             "dmverity super block has invalid number of data blocks (blocks: %" PRIu64 ", "
                             "data size: %" PRIu64 ")",
                             superBlock->dataBlocks, dataRange.size);
    }

    // Calculate the size of the hash tree for the given number of data blocks
    const size_t requiredHashBlocks = calcRequiredHashBlocks(superBlock->dataBlocks, blockSize);
    if ((requiredHashBlocks * superBlock->hashBlockSize) > (hashesRange.size - blockSize))
    {
        return Error::format(ErrorCode::DmVerityError,
                             "Not enough dm-verity hashes in file to cover the entire data (required hash blocks: %zu, "
                             "actual hashes size %" PRIu64 ")",
                             requiredHashBlocks, hashesRange.size);
    }

    // Copy the superblock structure and free the aligned memory buffer
    Result<VeritySuperBlock> result = *superBlock;
    alignedBuf.reset();

    return result;
}

// -----------------------------------------------------------------------------
/*!
    \static
    \internal

    Checks the supplied file ranges are valid for the supplied image file.

 */
Result<> DmVerityUtils::checkFileRanges(int imageFd, IDmVerityMounter::FileRange dataRange,
                                IDmVerityMounter::FileRange hashesRange)
{
    (void)imageFd;

    // All file offsets and sizes must be 4k aligned
    if (((dataRange.offset | dataRange.size | hashesRange.offset | hashesRange.size) & 0xfff) != 0)
    {
        return Error(ErrorCode::DmVerityError, "Data and hashes offsets and sizes must be 4k aligned");
    }

    // Check that the data part of the file is before the hashes (this is a requirement for dm-verity / devmapper driver)
    if (hashesRange.offset < (dataRange.offset + dataRange.size))
    {
        return Error(ErrorCode::DmVerityError, "dm-verity hashes must come after the data");
    }

    return Ok();
}
}