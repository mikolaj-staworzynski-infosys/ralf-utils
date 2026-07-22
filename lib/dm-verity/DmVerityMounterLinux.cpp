/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2025 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "DmVerityMounterLinux.h"
#include "DmVerityUtils.h"
#include "DevMapper.h"
#include "DmVerityMount.h"
#include "DmVeritySuperBlock.h"
#include "Error.h"
#include "core/Compatibility.h"
#include "core/LogMacros.h"

#include <fcntl.h>
#include <linux/loop.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <unistd.h>

#include <cstring>
#include <map>
#include <set>

#if defined(LIBRALF_NS)
using namespace LIBRALF_NS;
#endif

using namespace entos::ralf::dmverity;

// clang-format off
/// Macros for dealing with stuff on block boundaries
#define ROUND_UP(n, s) ((((n) + (s) - 1) / (s)) * (s))
#define DIV_ROUND_UP(n, d) (((n) + ((d) - 1)) / (d))
// clang-format on

/// The number of bytes in a sha256 hash block
#define SHA256_DIGEST_LENGTH (32)

static const std::map<IDmVerityMounter::FileSystemType, const char *> fsTypeNames = {
    { IDmVerityMounter::FileSystemType::Erofs, "erofs" },
    { IDmVerityMounter::FileSystemType::Squashfs, "squashfs" },
    { IDmVerityMounter::FileSystemType::Ext3, "ext3" },
    { IDmVerityMounter::FileSystemType::Ext4, "ext4" },
};


// -----------------------------------------------------------------------------
/*!
    \static
    \internal

    Performs the steps to mount the image:
        1. Checks the arguments and image is valid
        2. Loopback mount the image
        3. Create a devmapper device with the dm-verity details
        4. Mount the devmapper device to the mount point

 */
static Result<std::unique_ptr<IPackageMountImpl>> doMount(std::string_view name, IDmVerityMounter::FileSystemType fsType,
                                                          int imageFd, const std::filesystem::path &mountPoint,
                                                          IDmVerityMounter::FileRange dataRange,
                                                          IDmVerityMounter::FileRange hashesRange,
                                                          const std::vector<uint8_t> &rootHash,
                                                          const std::vector<uint8_t> &salt, MountFlags flags)
{
    // Currently the salt is not used, we read it from the dm-verity superblock if needed. Maybe in the future we will
    // use to verify the salt matches what was expected.
    (void)salt;

    // Sanity check the mount point is a directory and it exists
    std::error_code err;
    auto status = std::filesystem::symlink_status(mountPoint, err);
    if (status.type() != std::filesystem::file_type::directory)
        return Error::format(ErrorCode::InvalidArgument, "Mount point '%s' is not a directory", mountPoint.c_str());

    // Sanity check the supplied file offset
    auto checkResult = DmVerityUtils::checkFileRanges(imageFd, dataRange, hashesRange);
    if (!checkResult)
        return checkResult.error();

    // Read and check the dm-verity super block from the image
    const auto sb = DmVerityUtils::readDmVeritySuperBlock(imageFd, dataRange, hashesRange);
    if (!sb)
        return sb.error();

    // Check that the data size in the dm-verity header matches the expected data range supplied to the mount call
    if (dataRange.size != (sb->dataBlocks * sb->dataBlockSize))
    {
        return Error::format(ErrorCode::DmVerityError,
                             "The data size in the package doesn't match dm-verity superblock"
                             " (expect %" PRIu64 ", actual %" PRIu64 ")",
                             dataRange.size, (sb->dataBlocks * sb->dataBlockSize));
    }

    // Create a devmapper interface and make sure it's supported
    DevMapper devMapper;
    if (!devMapper.isAvailable())
        return Error(ErrorCode::DmVerityError, "Device mapper is not available on this system");

    // Generate a unique device name and uuid for the dm-verity device
    auto volumeNameAndUuid = DmVerityUtils::createDeviceNameAndUuid(devMapper, name, sb->uuid);
    if (!volumeNameAndUuid)
        return volumeNameAndUuid.error();

    const auto volumeName = std::move(volumeNameAndUuid->first);
    const auto volumeUuid = std::move(volumeNameAndUuid->second);

    logDebug("Generated devmapper device name '%s' and uuid '%s'", volumeName.c_str(), volumeUuid.c_str());

    // Find the outer bounds of the range
    const IDmVerityMounter::FileRange overallRange = { dataRange.offset,
                                                       (hashesRange.offset + hashesRange.size) - dataRange.offset };

    // Attach the image to a loop device
    auto loopDevFd = DmVerityUtils::loopDeviceAttach(imageFd, overallRange, flags);
    if (!loopDevFd)
        return loopDevFd.error();

    // Map the loop device using devmapper with dm-verity details
    auto mapperDevPath = devMapper.mapWithVerity(loopDevFd.value(), volumeName, volumeUuid,
                                                 (hashesRange.offset - overallRange.offset), dataRange.size, rootHash,
                                                 (flags & MountFlag::UDevSync) == MountFlag::UDevSync);

    // Close the loop device (if successfully mapped then loop device is maintained by kernel)
    if (close(loopDevFd.value()) != 0)
        logSysError(errno, "failed to close loop device");

    // Check if mapping succeeded
    if (!mapperDevPath)
        return mapperDevPath.error();

    // Create the mount flags, we always mount read-only as it's a dm-verity image, so no writes are allowed.
    unsigned long mountFlags = MS_RDONLY;
    if ((flags & MountFlag::NoDevice) == MountFlag::NoDevice)
        mountFlags |= MS_NODEV;
    if ((flags & MountFlag::NoSuid) == MountFlag::NoSuid)
        mountFlags |= MS_NOSUID;
    if ((flags & MountFlag::NoExec) == MountFlag::NoExec)
        mountFlags |= MS_NOEXEC;

    // We can now mount the devmapper device
    if (::mount(mapperDevPath->c_str(), mountPoint.c_str(), fsTypeNames.at(fsType), mountFlags, nullptr) != 0)
    {
        err = std::error_code(errno, std::system_category());

        devMapper.unmap(volumeName, volumeUuid, false);
        return Error::format(err, "Failed to mount dm-verity image '%s' at '%s'", mapperDevPath->c_str(),
                             mountPoint.c_str());
    }

    // Check the status of the device mapper device, this will return an error if the device is not found.
    // For dm-verity the status string is just a single character, a 'C' for corrupted and 'V' for valid
    // \see https://elixir.bootlin.com/linux/v5.4.277/source/drivers/md/dm-verity-target.c#L708
    auto dmStatus = devMapper.mapStatus(volumeName, volumeUuid);
    if (!dmStatus || (dmStatus.value() != "V"))
    {
        ::umount2(mountPoint.c_str(), MNT_FORCE);
        devMapper.unmap(volumeName, volumeUuid, false);

        if (!dmStatus)
            return dmStatus.error();
        else
            return Error(ErrorCode::DmVerityError, "Detected corruption in dm-verity image, cannot mount");
    }

    // Can now remove the mapping using 'deferred', meaning while it's mounted the mapping will remain, when unmounted
    // the kernel will clean up the mapping (and close the loop device which was also marked with autoclear)
    if ((flags & MountFlag::NoAutoClear) != MountFlag::NoAutoClear)
    {
        if (!devMapper.unmap(volumeName, volumeUuid, true))
            logError("Failed to unmap the image loop device - this may lead to future failures");
    }

    // Create the PackageMount object to return details of the mounted image
    return std::make_unique<DmVerityMount>(mapperDevPath.value(), mountPoint, volumeName, volumeUuid);
}

Result<std::unique_ptr<IPackageMountImpl>>
DmVerityMounterLinux::mount(std::string_view name, FileSystemType fsType, const std::filesystem::path &imagePath,
                            const std::filesystem::path &mountPoint, FileRange dataRange, FileRange hashesRange,
                            const std::vector<uint8_t> &rootHash, const std::vector<uint8_t> &salt, MountFlags flags) const
{
    // Open the image file, optionally with the O_DIRECT flag
    int openFlags = O_CLOEXEC | O_RDONLY;
    if ((flags & MountFlag::DirectIO) == MountFlag::DirectIO)
        openFlags |= O_DIRECT;

    int imageFd = open(imagePath.c_str(), openFlags);
    if (imageFd < 0)
    {
        // Not all filesystems support O_DIRECT (ie. tmpfs), so if we failed try opening without the O_DIRECT flag
        if ((openFlags & O_DIRECT) && (errno == EINVAL))
        {
            flags &= ~MountFlag::DirectIO;
            openFlags &= ~O_DIRECT;

            imageFd = open(imagePath.c_str(), openFlags);
            if (imageFd >= 0)
            {
                logWarning("Requested mount using directio mode, but image file is on a fs that doesn't support "
                           "O_DIRECT, disabling directio");
            }
        }

        if (imageFd < 0)
        {
            return Error::format(std::error_code(errno, std::system_category()), "Failed to open file @ '%s'",
                                 imagePath.c_str());
        }
    }

    auto result = doMount(name, fsType, imageFd, mountPoint, dataRange, hashesRange, rootHash, salt, flags);

    if (close(imageFd) != 0)
        logSysError(errno, "Failed to close image file");

    return result;
}

Result<std::unique_ptr<IPackageMountImpl>>
DmVerityMounterLinux::mount(std::string_view name, FileSystemType fsType, int imageFd,
                            const std::filesystem::path &mountPoint, FileRange dataRange, FileRange hashesRange,
                            const std::vector<uint8_t> &rootHash, const std::vector<uint8_t> &salt, MountFlags flags) const
{
    // Check that if directio was requested that the supplied fd was opened with O_DIRECT, or try and set it now
    if ((flags & MountFlag::DirectIO) == MountFlag::DirectIO)
    {
        int ret = fcntl(imageFd, F_GETFL, 0);
        if (ret < 0)
        {
            return Error(std::error_code(errno, std::system_category()), "Failed to get flags on image fd");
        }

        if ((ret & O_DIRECT) == 0)
        {
            // directio is not set on the fd, so try and open a new version of the file with that flag set (you can use
            // F_SETFL to set the O_DIRECT flag on the fd, but this would be messing with the caller supplied fd)
            const std::filesystem::path procLink = DmVerityUtils::procPathToFd(imageFd);
            return mount(name, fsType, procLink, mountPoint, dataRange, hashesRange, rootHash, salt, flags);
        }
    }

    return doMount(name, fsType, imageFd, mountPoint, dataRange, hashesRange, rootHash, salt, flags);
}

Result<> DmVerityMounterLinux::checkImageFile(FileSystemType fsType, int imageFd, FileRange dataRange,
                                              FileRange hashesRange) const
{
    (void)fsType;

    // Check the supplied file offsets
    auto checkResult = DmVerityUtils::checkFileRanges(imageFd, dataRange, hashesRange);
    if (!checkResult)
        return checkResult.error();

    // Read the dmverity super block from the image
    const auto sb = DmVerityUtils::readDmVeritySuperBlock(imageFd, dataRange, hashesRange);
    if (!sb)
        return sb.error();

    // Check that the data size in the dm-verity header matches the expected data range supplied to the mount call
    if (dataRange.size != (sb->dataBlocks * sb->dataBlockSize))
    {
        return Error::format(ErrorCode::DmVerityError,
                             "The data size in the package doesn't match dm-verity superblock"
                             " (expect %" PRIu64 ", actual %" PRIu64 ")",
                             dataRange.size, (sb->dataBlocks * sb->dataBlockSize));
    }

    return Ok();
}

Result<> DmVerityMounterLinux::checkImageFile(FileSystemType fsType, const std::filesystem::path &imagePath,
                                              FileRange dataRange, FileRange hashesRange) const
{
    // open the image file
    int imageFd = open(imagePath.c_str(), O_CLOEXEC | O_RDONLY);
    if (imageFd < 0)
    {
        return Error::format(std::error_code(errno, std::system_category()), "Failed to open image file @ '%s'",
                             imagePath.c_str());
    }

    auto result = checkImageFile(fsType, imageFd, dataRange, hashesRange);

    if (close(imageFd) != 0)
        logSysError(errno, "Failed to close image file");

    return result;
}
