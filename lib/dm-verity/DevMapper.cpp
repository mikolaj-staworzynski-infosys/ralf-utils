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

#include "DevMapper.h"
#include "UDevNotifySemaphore.h"
#include "core/LogMacros.h"

#include <atomic>
#include <cstring>
#include <sstream>
#include <thread>

#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#if defined(LIBRALF_NS)
using namespace LIBRALF_NS;
#endif

using namespace std::chrono_literals;
using namespace std::string_view_literals;
using namespace entos::ralf::dmverity;

// The default ioctl buffer size used by libdevmapper
static constexpr size_t DM_IOCTL_DEFAULT_BUFFER_SIZE = 16 * 1024;

// It's unclear what this flag is for, libdevmapper always sets it so we do too.
#ifndef DM_EXISTS_FLAG
#    define DM_EXISTS_FLAG 0x00000004
#endif

// These are the flags for the event_nr field and are used by udev to determine how to handle the device.
// See https://salsa.debian.org/lvm-team/lvm2/-/blob/main/device_mapper/all.h
#define DM_COOKIE_MAGIC 0x0D4D
#define DM_UDEV_FLAGS_MASK 0xFFFF0000
#define DM_UDEV_FLAGS_SHIFT 16

#define DM_UDEV_DISABLE_DM_RULES_FLAG 0x0001
#define DM_UDEV_DISABLE_SUBSYSTEM_RULES_FLAG 0x0002
#define DM_UDEV_DISABLE_DISK_RULES_FLAG 0x0004
#define DM_UDEV_DISABLE_OTHER_RULES_FLAG 0x0008
#define DM_UDEV_LOW_PRIORITY_FLAG 0x0010
#define DM_UDEV_DISABLE_LIBRARY_FALLBACK 0x0020
#define DM_UDEV_PRIMARY_SOURCE_FLAG 0x0040

DevMapper::DevMapper()
    : m_cmdBuffer(DM_IOCTL_DEFAULT_BUFFER_SIZE, 0x00)
{
    char controlPath[64];
    snprintf(controlPath, sizeof(controlPath), "/dev/%s/%s", DM_DIR, DM_CONTROL_NODE);

    // Open a connection to the device mapper control interface, this requires root privileges
    int fd = open(controlPath, O_RDWR | O_CLOEXEC);
    if (fd < 0)
    {
        logSysError(errno, "Failed to open '%s'", controlPath);
        return;
    }

    // Get the version of the device mapper interface
    auto *cmd = initialiseCmdBuf("", "");
    int rc = ioctl(fd, DM_VERSION, cmd);
    if (rc < 0)
    {
        logSysError(errno, "Failed to get device mapper version");
        close(fd);
        return;
    }

    m_version = VersionNumber(cmd->version[0], cmd->version[1], cmd->version[2]);
    if (m_version < VersionNumber(4, 6, 0))
    {
        logError("Unsupported device mapper version %u.%u.%u", cmd->version[0], cmd->version[1], cmd->version[2]);
        close(fd);
        return;
    }

    logInfo("Device mapper version %u.%u.%u is available", cmd->version[0], cmd->version[1], cmd->version[2]);

    m_controlFd = fd;
}

DevMapper::~DevMapper()
{
    if ((m_controlFd >= 0) && (close(m_controlFd) != 0))
    {
        logSysError(errno, "Failed to close device mapper control fd");
    }
}

bool DevMapper::isAvailable() const
{
    return (m_controlFd >= 0);
}

VersionNumber DevMapper::version() const
{
    return m_version;
}

// -----------------------------------------------------------------------------
/*!
    \static
    \internal

    Converts a byte array \a bytes or \a length to a lower case hex string.

 */
std::string DevMapper::toHex(const uint8_t *bytes, size_t length)
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

    Creates the mapper target params for dm-verity.  This is mostly details from
    the hashes superblock, but also requires the details of the loop device and
    the root hash.

    \see https://docs.kernel.org/admin-guide/device-mapper/verity.html
 */
std::string DevMapper::createTargetParams(unsigned loopDevMajor, unsigned loopDevMinor,
                                          const VeritySuperBlock &superBlock, const std::vector<uint8_t> &rootHash,
                                          uint64_t hashesOffset)
{
    std::ostringstream params;

    // The hashesOffset supplied is the byte offset of the dmverity superblock, whereas devmapper wants the offset of
    // the first hash in hash blocks, so convert here.
    hashesOffset += sizeof(VeritySuperBlock);
    hashesOffset += superBlock.hashBlockSize - 1;
    hashesOffset /= superBlock.hashBlockSize;

    // build the params
    params << superBlock.hashType << ' '                 // hash type
           << loopDevMajor << ':' << loopDevMinor << ' ' // data device loop device
           << loopDevMajor << ':' << loopDevMinor << ' ' // hashes device loop device (same as data device)
           << superBlock.dataBlockSize << ' ' << superBlock.hashBlockSize << ' ' << superBlock.dataBlocks << ' '
           << hashesOffset << ' ' << reinterpret_cast<const char *>(superBlock.algorithm) << ' '
           << toHex(rootHash.data(), rootHash.size()) << ' ' << toHex(superBlock.salt, superBlock.saltSize);

    // If features are used, the string should start with a number identifying how many features are present, followed
    // by space separated feature strings, see https://docs.kernel.org/admin-guide/device-mapper/verity.html for a list
    // of possible features.

    return params.str();
}

// -----------------------------------------------------------------------------
/*!
    \static
    \internal

    Reads and sanity checks the dmverity superblock from the given \a imageFileFd
    at the given \a offset.

 */
Result<VeritySuperBlock> DevMapper::readDmVeritySuperBlock(int devFd, uint64_t hashesOffset)
{
    constexpr uint64_t blockSize = 4096;

    // If O_DIRECT was used to open the image file then all reads need to block aligned, hence the allocation of
    // memaligned buffer
    std::unique_ptr<uint8_t, decltype(std::free) *> alignedBuf(reinterpret_cast<uint8_t *>(
                                                                   std::aligned_alloc(4096, blockSize)),
                                                               std::free);

    // Read the super block
    const ssize_t rd = TEMP_FAILURE_RETRY(pread(devFd, alignedBuf.get(), blockSize, static_cast<off_t>(hashesOffset)));
    if (rd != blockSize)
        return Error(std::error_code(errno, std::system_category()), "Failed to read image file");

    // Sanity check the superblock fields
    const auto *superBlock = reinterpret_cast<const VeritySuperBlock *>(alignedBuf.get());
    auto checkResult = checkSuperBlock(superBlock);
    if (!checkResult)
        return checkResult.error();

    // Copy the superblock structure and free the aligned memory buffer
    Result<VeritySuperBlock> result = *superBlock;
    alignedBuf.reset();

    return result;
}

// -----------------------------------------------------------------------------
/*!
    \internal

    Initialises the command buffer for the device mapper ioctl commands.

 */
dm_ioctl *DevMapper::initialiseCmdBuf(std::string_view name, std::string_view uuid) const
{
    auto *buf = reinterpret_cast<dm_ioctl *>(m_cmdBuffer.data());
    memset(buf, 0x00, m_cmdBuffer.size());

    buf->version[0] = 4;
    buf->version[1] = 0;
    buf->version[2] = 0;
    buf->data_size = m_cmdBuffer.size();
    buf->data_start = sizeof(dm_ioctl);
    buf->flags |= DM_EXISTS_FLAG;
    memcpy(buf->name, name.data(), std::min<size_t>(name.size(), DM_NAME_LEN - 1));
    memcpy(buf->uuid, uuid.data(), std::min<size_t>(uuid.size(), DM_UUID_LEN - 1));

    return buf;
}

// -----------------------------------------------------------------------------
/*!
    \static
    \internal

    This talks to the kernel devmapper driver to create a new mapped device using
    the loopback block device and associating it with the dm-verity hash tree that
    is also stored on the loopback block device.

 */
Result<> DevMapper::createDevice(uint64_t dataSize, std::string_view deviceName, std::string_view deviceUuid,
                                 std::string_view targetType, std::string_view targetParams, bool readOnly) const
{
    // Check that the dm-verity parameters fit within our command buffer
    if (targetParams.size() >= (m_cmdBuffer.size() - sizeof(dm_ioctl) - sizeof(dm_target_spec)))
    {
        return Error(ErrorCode::DmVerityError, "devmapper target parameters are too large");
    }

    // Create the device
    auto *cmd = initialiseCmdBuf(deviceName, deviceUuid);
    int rc = ioctl(m_controlFd, DM_DEV_CREATE, cmd);
    if (rc < 0)
    {
        return Error(std::error_code(errno, std::system_category()), "Failed to create device mapper dm-verity device");
    }

    // Load a "verity" table for the device
    cmd = initialiseCmdBuf(deviceName, ""sv);
    cmd->target_count = 1;
    cmd->flags |= DM_SECURE_DATA_FLAG;
    if (readOnly)
        cmd->flags |= DM_READONLY_FLAG;

    auto *target = reinterpret_cast<dm_target_spec *>(cmd + 1);
    target->sector_start = 0;
    target->length = (dataSize / 512);

    const size_t targetTypeLen = std::min<size_t>(targetType.size(), DM_MAX_TYPE_NAME - 1);
    memcpy(target->target_type, targetType.data(), targetTypeLen);
    target->target_type[targetTypeLen] = '\0';

    auto *params = reinterpret_cast<char *>(target + 1);
    const size_t targetParamsLen =
        std::min<size_t>(targetParams.size(), (cmd->data_size - cmd->data_start - sizeof(dm_target_spec) - 1));
    memcpy(params, targetParams.data(), targetParamsLen);
    params[targetParamsLen] = '\0';

    rc = ioctl(m_controlFd, DM_TABLE_LOAD, cmd);
    if (rc < 0)
    {
        removeDevice(deviceName, deviceUuid, false);

        return Error(std::error_code(errno, std::system_category()),
                     "Failed to load table for dm-verity device in devmapper");
    }

    return Ok();
}

// -----------------------------------------------------------------------------
/*!
    \internal

    Attempts to activate the device with the given \a name and \a uuid. If
    \a wait is true then the function will block until the device is activated,

 */
Result<dev_t> DevMapper::activateDevice(std::string_view name, std::string_view uuid, const bool readOnly,
                                        const bool useUDevSync) const
{
    // Initialise the command buffer
    auto *cmd = initialiseCmdBuf(name, ""sv);

    // This is set by libdevmapper, so we set as well
    cmd->flags |= DM_SECURE_DATA_FLAG;

    // Set the read-only flag if requested, this should be set for dm-verity mappings.
    if (readOnly)
        cmd->flags |= DM_READONLY_FLAG;

    // The event_nr value is split into two parts, the lower 16 bits can be used to identify a semaphore that udev
    // can use to indicate when the device rules have been processed, for example udev has reported that it has
    // created the symlink for the device in /dev/mapper.  The upper 16 bits are flags that are used to control how udev
    // handles the device.

    // The question is whether this library should be relying on udev or not, I don't think it strictly needs to, as
    // the (successful) ioctl call will return the new device node major and minor numbers.  But the problem is that
    // we can't use those numbers to mount, we need a device node (which udev creates).  We could temporarily create a
    // device node, just for mounting, but that seems a bit hacky.  So the code does implement a udev notify semaphore
    // to wait for udev to process the device, but it's opt-in and on most RDK platforms it won't work because they
    // don't have the lvm2 udev rules installed.

    Result<UDevNotifySemaphore> cookieSem;
    if (useUDevSync)
    {
        cookieSem = UDevNotifySemaphore::create();
        if (!cookieSem)
            logError("Failed to create udev notify semaphore for device: %s", cookieSem.error().what());
        else
            cmd->event_nr = cookieSem->cookie();
    }

    if (!cookieSem)
    {
        cmd->event_nr = (DM_UDEV_DISABLE_LIBRARY_FALLBACK | DM_UDEV_PRIMARY_SOURCE_FLAG) << DM_UDEV_FLAGS_SHIFT;
    }

    // Resume the device (yes confusingly the icoctl is called "suspend" but it actually resumes the device)
    int rc = ioctl(m_controlFd, DM_DEV_SUSPEND, cmd);
    if (rc < 0)
    {
        return Error(std::error_code(errno, std::system_category()),
                     "Failed to activate device mapper dm-verity device");
    }

    logInfo("devmapper activated device '%*s' with uuid '%*s' and gave it device number %u:%u",
            static_cast<int>(name.size()), name.data(), static_cast<int>(uuid.size()), uuid.data(), major(cmd->dev),
            minor(cmd->dev));

    // Wait for udev to process the device
    if (cookieSem)
    {
        const auto result = cookieSem->wait(1s);
        if (!result)
        {
            logError("Failed to wait for udev to process device mapper dm-verity device '%*s': %s",
                     static_cast<int>(name.size()), name.data(), result.error().what());
        }
    }

    return static_cast<dev_t>(cmd->dev);
}

// -----------------------------------------------------------------------------
/*!
    \internal

    Communicates with the device mapper to get the status of the device with the
    given \a name and/or \a uuid.  This will return an error if the device is not
    found.

 */
Result<std::string> DevMapper::deviceStatus(std::string_view name, std::string_view uuid) const
{
    (void)uuid;

    // Initialise the command buffer
    auto *cmd = initialiseCmdBuf(name, ""sv);

    // Set by libdevmapper, so we set as well
    cmd->flags |= DM_NOFLUSH_FLAG;

    // Get the status of the mapping
    int rc = ioctl(m_controlFd, DM_TABLE_STATUS, cmd);
    if (rc < 0)
    {
        return Error(std::error_code(errno, std::system_category()), "Failed to get status of dm-verity device");
    }

    // The response buffer is filled with the status of the device, we can check
    if (cmd->data_size < sizeof(dm_ioctl) + sizeof(dm_target_spec))
        return Error(ErrorCode::DmVerityError, "Device mapper response buffer is too small");
    if (cmd->data_size > m_cmdBuffer.size())
        return Error(ErrorCode::DmVerityError, "Device mapper response buffer is too large");
    if ((cmd->data_start < sizeof(dm_ioctl)) || (cmd->data_start >= cmd->data_size))
        return Error(ErrorCode::DmVerityError, "Device mapper response buffer has invalid data start offset");

    if (cmd->target_count < 1)
        return Error(ErrorCode::DmVerityError, "Device mapper device has no targets");

    const auto *target = reinterpret_cast<const dm_target_spec *>(m_cmdBuffer.data() + cmd->data_start);
    logDebug("dm-verity table status target { start=%" PRIu64 ", length=%" PRIu64 ", status=%u, next=%u, type='%s' }",
             uint64_t(target->sector_start), uint64_t(target->length), target->status, target->next, target->target_type);

    if (target->sector_start != 0)
    {
        logWarning("Invalid sector start for device '%*s', expected 0, got %" PRIu64, static_cast<int>(name.size()),
                   name.data(), uint64_t(target->sector_start));
    }
    if (strncmp(target->target_type, "verity", DM_MAX_TYPE_NAME) != 0)
    {
        logWarning("devmapper device '%*s' is not a dm-verity virtual device", static_cast<int>(name.size()),
                   name.data());
    }

    // We trust that the kernel driver has null-terminated the params string, libdevmapper seems to assume this,
    // so we do too.  I initially thought we should use the next field to determine the length of the params string, but
    // that is not the case, it seems to be set incorrectly by the kernel driver if only one target is present.
    const auto *params = reinterpret_cast<const char *>(target + 1);
    logInfo("devmapper device '%.*s' has status '%s'", static_cast<int>(name.size()), name.data(), params);

    return std::string(params);
}

// -----------------------------------------------------------------------------
/*!
    \internal

    Attempts to remove the device with the given \a name and \a uuid from the
    device mapper.  If the device is not found or is currently in use then an
    error is returned.

    \a deferred is used to indicate if the device should be removed immediately or
    if it should be marked for removal and removed later when it is no longer in use,
    for example when it is unmounted.

 */
Result<> DevMapper::removeDevice(std::string_view name, std::string_view uuid, bool deferred) const
{
    (void)uuid;

    // Initialise the command buffer
    auto *cmd = initialiseCmdBuf(name, ""sv);

    // If deferred is true then we don't actually remove the device, we just mark it for removal
    if (deferred)
        cmd->flags |= DM_DEFERRED_REMOVE;

    // The use of event_nr is not very well documented and complex, it seems to be used to communicate with udev
    // by setting a cookie value in the kernels uevent that udev can use to control behaviour in regard to the device.
    // When removing a device we don't really care about synchronising with udev, so set the standard flags but
    // don't set a semaphore value.
    cmd->event_nr = (DM_UDEV_DISABLE_LIBRARY_FALLBACK | DM_UDEV_PRIMARY_SOURCE_FLAG) << DM_UDEV_FLAGS_SHIFT;

    // Remove the device
    int rc = ioctl(m_controlFd, DM_DEV_REMOVE, cmd);
    if (rc < 0)
    {
        return Error(std::error_code(errno, std::system_category()), "Failed to remove device mapper dm-verity device");
    }

    return Ok();
}

// -----------------------------------------------------------------------------
/*!
    \internal
    \static

    Given a \a dev number of a block device, this function attempts to find the
    device node that corresponds to the device.

    This is simply done by first looking for the udev created /dev/block/MAJOR:MINOR
    symlink, and if that is not found then scanning /dev for block devices with
    matching major/minor numbers.

 */
Result<std::filesystem::path> DevMapper::findDeviceNode(dev_t dev)
{
    static const std::filesystem::path devDir = "/dev/";

    char fname[96];
    snprintf(fname, sizeof(fname), "block/%u:%u", major(dev), minor(dev));
    std::filesystem::path blockDevPath = devDir / fname;

    struct stat buf = {};

    // We are potentially racing with udev creating the device node, so we may need to retry a few times
    const int maxRetries = 5;
    for (int attempt = 0; attempt < maxRetries; attempt++)
    {
        // Check the dev node created is present and a block device
        if ((stat(blockDevPath.c_str(), &buf) == 0) && S_ISBLK(buf.st_mode) && (buf.st_rdev == dev))
        {
            logDebug("devmapper found mapped block device %u:%u at '%s'", major(dev), minor(dev), blockDevPath.c_str());
            return blockDevPath;
        }

        // If the /dev/block/MAJOR:MINOR symlink is not present, or is not a block device, then scan /dev for a
        // matching block device.  This will probably be /dev/dm-X but could be elsewhere.
        std::error_code err;
        for (const auto &entry : std::filesystem::directory_iterator(devDir, err))
        {
            if (!entry.is_block_file(err))
                continue;

            const auto &path = entry.path();
            if (stat(path.c_str(), &buf) != 0)
                continue;

            if (S_ISBLK(buf.st_mode) && (buf.st_rdev == dev))
            {
                logDebug("devmapper found mapped block device %u:%u at '%s'", major(dev), minor(dev), path.c_str());
                return path;
            }
        }

        // Sleep a bit before retrying
        std::this_thread::sleep_for(20ms * (attempt + 1));
    }

    return Error::format(std::error_code(errno, std::system_category()),
                         "devmapper failed to find mapped block device %d:%d", major(dev), minor(dev));
}

// -----------------------------------------------------------------------------
/*!
    \internal
    \static

    Helper to check that the supplied \a name and \a uuid are valid for use with
    the device mapper.

 */
Result<> DevMapper::checkDeviceNameAndUuid(std::string_view name, std::string_view uuid)
{
    if ((name.size() >= DM_NAME_LEN) || (name.find('/') != std::string::npos))
        return Error(ErrorCode::DmVerityError, "Invalid device name for devmapper");

    if (uuid.size() >= DM_UUID_LEN)
        return Error(ErrorCode::DmVerityError, "Invalid device uuid for devmapper");

    return Ok();
}

Result<std::filesystem::path> DevMapper::mapWithVerity(int devFd, std::string_view name, std::string_view uuid,
                                                       uint64_t hashOffset, uint64_t dataSize,
                                                       const std::vector<uint8_t> &rootHash, bool useUDevSync) const
{
    // Sanity check the devmapper is available
    if (!isAvailable())
        return Error(ErrorCode::DmVerityError, "Device mapper is not available");

    // Check the device name and uuid fit within the limits of the device mapper
    auto checkResult = checkDeviceNameAndUuid(name, uuid);
    if (!checkResult)
        return checkResult.error();

    // Sanity check the root hash size, we only support SHA256 for now so the root hash must be 32 bytes
    if (rootHash.size() != 32)
        return Error(ErrorCode::DmVerityError, "Invalid root hash size, only SHA256 is supported");

    // Must supply a name or uuid at a minimum, if both are empty then we can't add the device.
    if (name.empty() && uuid.empty())
        return Error(ErrorCode::DmVerityError, "Must supply a device name and/or uuid to map a device");

    // Get the major and minor number of the loopback block device
    struct stat loopDevStat = {};
    if ((fstat(devFd, &loopDevStat) != 0))
        return Error(std::error_code(errno, std::system_category()), "Failed to get loop device stat");
    if (!S_ISBLK(loopDevStat.st_mode))
        return Error(ErrorCode::DmVerityError, "Supplied loop device is not a block device");

    // Get the block size of the loop device
    int loopDevBlkSize;
    if (ioctl(devFd, BLKSSZGET, &loopDevBlkSize) != 0)
        return Error(std::error_code(errno, std::system_category()), "Failed to get loop device block size");

    // Sanity check the data size and hash offset are block aligned
    if ((dataSize % loopDevBlkSize) != 0 || (hashOffset % loopDevBlkSize) != 0)
        return Error(ErrorCode::DmVerityError, "dm-verity superblock or data is not block aligned");

    // Read the dm-verity super block from the loopback device
    auto superBlock = readDmVeritySuperBlock(devFd, hashOffset);
    if (!superBlock)
        return superBlock.error();

    // Check that the data size in the dm-verity header matches the expected data range supplied to the mount call
    if (dataSize != (superBlock->dataBlocks * superBlock->dataBlockSize))
    {
        return Error::format(ErrorCode::DmVerityError,
                             "The data size in the package doesn't match dm-verity superblock (expect %" PRIu64
                             ", actual %" PRIu64 ")",
                             dataSize, (superBlock->dataBlocks * superBlock->dataBlockSize));
    }

    // Create the mapper target params
    const std::string targetParams = createTargetParams(major(loopDevStat.st_rdev), minor(loopDevStat.st_rdev),
                                                        superBlock.value(), rootHash, hashOffset);

    // Use devmapper to associate the dm-verity info with loopback mounted image
    auto createResult = createDevice(dataSize, name, uuid, "verity"sv, targetParams, true);
    if (!createResult)
    {
        return createResult.error();
    }

    // Activate the device, this will return the major and minor numbers of the new device node
    auto activateResult = activateDevice(name, uuid, true, useUDevSync);
    if (!activateResult)
    {
        removeDevice(name, uuid, false);
        return activateResult.error();
    }

    // Finally try and find the device node that has been created for the dm-verity device.
    auto devNodePath = findDeviceNode(activateResult.value());
    if (!devNodePath)
    {
        removeDevice(name, uuid, false);
        return devNodePath.error();
    }

    return devNodePath;
}

Result<std::filesystem::path> DevMapper::mapWithCrypt(std::string_view devicePath, std::string_view name,
                                                      std::string_view uuid, uint64_t deviceSize,
                                                      const std::string &cipher, const std::string &keyType,
                                                      const std::string &keyDescription, size_t keySize,
                                                      uint64_t ivOffset, uint64_t dataOffset,
                                                      uint32_t sectorSize, bool useUDevSync) const
{
    // Sanity check the devmapper is available
    if (!isAvailable())
        return Error(ErrorCode::DmVerityError, "Device mapper is not available");

    // Check the device name and uuid fit within the limits of the device mapper
    auto checkResult = checkDeviceNameAndUuid(name, uuid);
    if (!checkResult)
        return checkResult.error();

    // The mapped device covers only the encrypted data area, i.e. the device minus the LUKS header
    if (deviceSize <= dataOffset * 512)
        return Error(ErrorCode::DmVerityError, "Invalid data offset for dm-crypt device");
    const uint64_t mappedSize = deviceSize - dataOffset * 512;

    // Build the dm-crypt target params:
    //   <cipher> <key> <iv_offset> <device> <offset> [<#opt_params> <opt_params>]
    // The key is a kernel key service reference (":<key_size>:<key_type>:<key_description>") -
    // the kernel resolves it from the keyring itself, so the payload never enters userspace.
    // See https://docs.kernel.org/admin-guide/device-mapper/dm-crypt.html
    std::ostringstream params;
    params << cipher << " :" << keySize << ':' << keyType << ':' << keyDescription << ' ' << ivOffset << ' '
           << devicePath << ' ' << dataOffset;
    if (sectorSize != 512)
        params << " 1 sector_size:" << sectorSize;

    logInfo("dm-crypt table: 0 %" PRIu64 " crypt %s", mappedSize / 512, params.str().c_str());

    // Use devmapper to create the dm-crypt device on top of the loop device
    auto createResult = createDevice(mappedSize, name, uuid, "crypt"sv, params.str(), true);
    if (!createResult)
        return createResult.error();

    // Activate the device, this will return the major and minor numbers of the new device node
    auto activateResult = activateDevice(name, uuid, true, useUDevSync);
    if (!activateResult)
    {
        removeDevice(name, uuid, false);
        return activateResult.error();
    }

    // Finally try and find the device node that has been created for the dm-crypt device.
    auto devNodePath = findDeviceNode(activateResult.value());
    if (!devNodePath)
    {
        removeDevice(name, uuid, false);
        return devNodePath.error();
    }

    return devNodePath;
}

Result<> DevMapper::unmap(std::string_view name, std::string_view uuid, bool deferred) const
{
    // Sanity check the devmapper is available
    if (!isAvailable())
        return Error(ErrorCode::DmVerityError, "Device mapper is not available");

    // Check the device name and uuid fit within the limits of the device mapper
    auto checkResult = checkDeviceNameAndUuid(name, uuid);
    if (!checkResult)
        return checkResult.error();

    // Must supply a name of uuid at a minimum, if both are empty then we can't remove the device.
    if (name.empty() && uuid.empty())
        return Error(ErrorCode::DmVerityError, "Must supply a device name and/or uuid to remove");

    // Remove the device
    return removeDevice(name, uuid, deferred);
}

Result<std::string> DevMapper::mapStatus(std::string_view name, std::string_view uuid) const
{
    // Sanity check the devmapper is available
    if (!isAvailable())
        return Error(ErrorCode::DmVerityError, "Device mapper is not available");

    // Check the device name and uuid fit within the limits of the device mapper
    auto checkResult = checkDeviceNameAndUuid(name, uuid);
    if (!checkResult)
        return checkResult.error();

    // Must supply a name of uuid at a minimum, if both are empty then we can't get the status of the device
    if (name.empty() && uuid.empty())
        return Error(ErrorCode::DmVerityError, "Must supply a device name and/or uuid to remove");

    return deviceStatus(name, uuid);
}

// -----------------------------------------------------------------------------
/*!
    Returns the list of currently mapped devices in the device mapper.  The list
    consists of the device number and the name of the mapped device.

 */
Result<std::list<DevMapper::MappedDevice>> DevMapper::mappedDevices() const
{
    // Sanity check the devmapper is available
    if (!isAvailable())
        return Error(ErrorCode::DmVerityError, "Device mapper is not available");

    std::list<MappedDevice> devices;

    // Initialise the command buffer
    auto *cmd = initialiseCmdBuf(""sv, ""sv);

    // List all the devices
    int rc = ioctl(m_controlFd, DM_LIST_DEVICES, cmd);
    if ((rc < 0) || (cmd->data_size > m_cmdBuffer.size()) || (cmd->data_start > cmd->data_size) ||
        (cmd->data_start < sizeof(dm_ioctl)))
    {
        return Error(std::error_code(errno, std::system_category()), "Failed to get list of mapped devices");
    }

    //
    char nameBuf[DM_NAME_LEN + 1] = {};

    // The response buffer is filled with the list of devices, we can check
    size_t offset = cmd->data_start;
    while ((offset + sizeof(dm_name_list)) <= cmd->data_size)
    {
        // Read the next entry
        const auto *entry = reinterpret_cast<const dm_name_list *>(m_cmdBuffer.data() + offset);

        size_t maxNameLen;
        if (entry->next == 0)
            maxNameLen = cmd->data_size - offset - sizeof(dm_name_list);
        else
            maxNameLen = entry->next - sizeof(dm_name_list);
        if (maxNameLen > DM_NAME_LEN)
            maxNameLen = DM_NAME_LEN;

        strncpy(nameBuf, entry->name, maxNameLen);

        logDebug("Found mapped device: dev=%u:%u, name='%s'", major(entry->dev), minor(entry->dev), nameBuf);

        devices.emplace_back(MappedDevice{ static_cast<dev_t>(entry->dev), nameBuf });

        if (entry->next == 0)
            break;

        offset += entry->next;
    }

    return devices;
}