#include "LuksVerityMount.h"
#include "dm-verity/DevMapper.h"
#include "core/LogMacros.h" 
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libcryptsetup.h>

#if defined(LIBRALF_NS)
using namespace LIBRALF_NS;
#endif

namespace entos::ralf::dmverity {

LuksVerityMount::LuksVerityMount(std::filesystem::path devicePath, std::filesystem::path mountPoint,
                                 std::string_view volumeName, std::string_view volumeUuid,
                                 std::string_view luksVolumeName, bool autoClear)
    : m_devicePath(std::move(devicePath))
    , m_mountPoint(std::move(mountPoint))
    , m_volumeName(volumeName)
    , m_volumeUuid(volumeUuid)
    , m_luksVolumeName(luksVolumeName)
    , m_autoClear(autoClear)
{
    struct stat buf = {};
    if (stat(m_devicePath.c_str(), &buf) != 0)
    {
        logSysError(errno, "Failed to stat device node '%s'", m_devicePath.c_str());
        return;
    }
    if (!S_ISBLK(buf.st_mode))
    {
        logError("Mounted device '%s' is not a block device", m_devicePath.c_str());
        return;
    }

    m_deviceNumber = buf.st_rdev;
}

LuksVerityMount::~LuksVerityMount()
{
    if (!m_detached && !m_unmounted)
    {
        doUnmount();
    }
}

void LuksVerityMount::doUnmount()
{
    logInfo("Unmounting %s", m_mountPoint.c_str());
    if (::umount2(m_mountPoint.c_str(), UMOUNT_NOFOLLOW) != 0)
    {
        logSysError(errno, "Failed to unmount luks-verity filesystem at '%s'", m_mountPoint.c_str());
    }
    if (m_autoClear)
    {
        logInfo("AutoClear active. Kernel handles device removal if all mountpoints released.");
        logInfo("Auto removal for LUKS: %s", m_luksVolumeName.c_str());
        logInfo("Auto removal for DM-VERITY: %s", m_volumeName.c_str());
        return; 
    }

    DevMapper devMapper;
    logInfo("Unmapping %s", m_volumeName.c_str());
    if (!devMapper.unmap(m_volumeName, m_volumeUuid, false))
    {
        logError("Failed to unmap verity device '%s'", m_volumeName.c_str());
    }

    logInfo("Crypt deactivate %s", m_luksVolumeName.c_str());
    int rc = crypt_deactivate(nullptr, m_luksVolumeName.c_str());
    if (rc < 0)
    {
        logError("Failed to deactivate LUKS device '%s' (error code: %d)", m_luksVolumeName.c_str(), rc);
    }
}

bool LuksVerityMount::isMounted() const
{
    if (m_unmounted)
        return false;

    if (m_deviceNumber == 0)
    {
        logError("Device number is not set, cannot check if mounted");
        return false;
    }

    struct stat buf = {};
    if (stat(m_mountPoint.c_str(), &buf) != 0)
    {
        if (errno != ENOENT)
            logSysError(errno, "Failed to stat device node '%s'", m_devicePath.c_str());

        return false;
    }

    return (buf.st_dev == m_deviceNumber);
}

std::filesystem::path LuksVerityMount::mountPoint() const
{
    if (m_unmounted)
        return {};

    return m_mountPoint;
}

void LuksVerityMount::unmount()
{
    if (m_unmounted)
        return;

    doUnmount();
    m_unmounted = true;
}

void LuksVerityMount::detach()
{
    m_detached = true;
}

std::string LuksVerityMount::volumeName() const
{
    if (m_unmounted)
        return {};

    return m_volumeName;
}

std::string LuksVerityMount::volumeUuid() const
{
    if (m_unmounted)
        return {};

    return m_volumeUuid;
}

MountStatus LuksVerityMount::status() const
{
    if (!isMounted())
        return MountStatus::NotMounted;

    DevMapper devMapper;
    if (!devMapper.isAvailable())
    {
        logError("Device mapper is not available, cannot check mount status");
        return MountStatus::Mounted;
    }

    auto status = devMapper.mapStatus(m_volumeName, m_volumeUuid);
    if (!status)
    {
        logError("Failed to get device mapper status: %s", status.error().what());
        return MountStatus::Mounted;
    }

    if (status.value() == "C")
        return MountStatus::Corrupted;

    if (status.value() != "V")
        logError("Unexpected device mapper status '%s' for '%s'", status.value().c_str(), m_volumeName.c_str());

    return MountStatus::Mounted;
}

} // namespace entos::ralf::dmverity
