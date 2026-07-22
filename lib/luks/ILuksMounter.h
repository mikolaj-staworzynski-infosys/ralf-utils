#pragma once

#include "dm-verity/IDmVerityMounter.h"

namespace entos::ralf::dmverity
{
    class ILuksMounter
    {
    public:
        virtual ~ILuksMounter() = default;

        using FileSystemType = IDmVerityMounter::FileSystemType;
        using FileRange = IDmVerityMounter::FileRange;

        virtual Result<std::unique_ptr<IPackageMountImpl>>
        mount(std::string_view name, FileSystemType fsType, int imageFd, const std::filesystem::path &mountPoint, FileRange luksRange, FileRange hashRange,
              const std::vector<uint8_t> &rootHash, const std::vector<uint8_t> &salt,
              const std::string &keyMaterial, MountFlags flags) const = 0;

        virtual Result<> checkImageFile(FileSystemType fsType, int imageFd, FileRange luksRange) const = 0;
    };
} // namespace entos::ralf::dmverity
