#pragma once

#include "core/IPackageMountImpl.h"
#include <filesystem>
#include <string>

namespace entos::ralf::dmverity {

class LuksVerityMount : public IPackageMountImpl {
public:
    LuksVerityMount(std::filesystem::path devicePath, std::filesystem::path mountPoint,
                    std::string_view volumeName, std::string_view volumeUuid,
                    std::string_view luksVolumeName, bool autoClear);
    
    ~LuksVerityMount() override;

    std::filesystem::path mountPoint() const override;

    bool isMounted() const override;
    void unmount() override;
    void detach() override;
    std::string volumeName() const override;
    std::string volumeUuid() const override;
    MountStatus status() const override;

private:
    void doUnmount();

    std::filesystem::path m_devicePath;
    std::filesystem::path m_mountPoint;
    std::string m_volumeName;
    std::string m_volumeUuid;
    std::string m_luksVolumeName;
    bool m_autoClear;
    dev_t m_deviceNumber = 0;
    bool m_unmounted = false;
    bool m_detached = false;
};

} // namespace entos::ralf::dmverity
