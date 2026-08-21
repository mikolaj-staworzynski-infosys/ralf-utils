#pragma once

#include "dm-verity/IDmVerityMounter.h"
#include "luks/ILuksMounter.h"
#include "Result.h"
#include "core/IPackageMountImpl.h"

#include <filesystem>
#include <string_view>
#include <vector>

namespace entos::ralf::dmverity
{

    class LuksMounterLinux final : public ILuksMounter
    {
    public:
        LuksMounterLinux() = default;
        ~LuksMounterLinux() override = default;

        Result<std::unique_ptr<LIBRALF_NS::IPackageMountImpl>>
        mount(std::string_view name, FileSystemType fsType, int imageFd, const std::filesystem::path &mountPoint, FileRange luksRange, FileRange hashRange,
              const std::vector<uint8_t> &rootHash, const std::vector<uint8_t> &salt, const std::string &keyMaterial,
              LIBRALF_NS::MountFlags flags) const override;

        Result<> checkImageFile(FileSystemType fsType, int imageFd, FileRange luksRange) const override;
    private:
        Result<std::vector<uint8_t>> unwrapKeyMaterial(const std::vector<uint8_t>& wrappedKey, const std::filesystem::path& jwkPath);
        // Activate the LUKS volume with the volume key referenced from the kernel
        // keyring (dm-crypt key service) - the key payload never enters process RAM.
        // Returns the device node of the decrypted dm-crypt device.
        Result<std::filesystem::path> luksActivateFromKeyring(const std::string& loopDevPath, const std::string& luksVolumeName, const std::string& keyDesc, bool useUDevSync);
        Result<std::unique_ptr<IPackageMountImpl>> doMount(std::string_view name, FileSystemType fsType, int imageFd, 
                          const std::filesystem::path &mountPoint, FileRange luksRange, FileRange hashRange, const std::vector<uint8_t> &rootHash,
                          const std::vector<uint8_t> &wrappedKey, MountFlags flags);
        bool isMasterKeyInCache(const std::string& keyDesc);
        bool saveMasterKeyToCache(const std::vector<uint8_t>& wrappedKey, const std::vector<uint8_t>& key);
    };
} // namespace entos::ralf::dmverity
