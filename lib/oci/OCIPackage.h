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

#pragma once

#include "Result.h"
#include "core/IPackageImpl.h"

#include <atomic>
#include <climits>
#include <filesystem>
#include <list>
#include <memory>
#include <mutex>
#include <optional>

class IOCIBackingStore;
class IOCIFileReader;
class OCIDescriptor;

namespace entos::ralf::dmverity
{
    class IDmVerityMounter;
    class ILuksMounter;
}

// -------------------------------------------------------------------------
/*!
    \class OCIPackage
    \brief Implement of a package that uses the OCI packaging format (tar file).


 */
class OCIPackage final : public LIBRALF_NS::IPackageImpl
{
public:
    static std::unique_ptr<OCIPackage> open(int packageFd, const std::optional<LIBRALF_NS::VerificationBundle> &bundle,
                                            LIBRALF_NS::Package::OpenFlags flags, LIBRALF_NS::Error *_Nullable error);

    static std::unique_ptr<OCIPackage> open(std::shared_ptr<IOCIBackingStore> backingStore,
                                            const std::optional<LIBRALF_NS::VerificationBundle> &bundle,
                                            LIBRALF_NS::Package::OpenFlags flags, LIBRALF_NS::Error *_Nullable error);

public:
    OCIPackage(std::shared_ptr<IOCIBackingStore> &&backingStore,
               std::shared_ptr<entos::ralf::dmverity::IDmVerityMounter> &&dmVerityMounter,
               std::shared_ptr<entos::ralf::dmverity::ILuksMounter> &&luksMounter,
               LIBRALF_NS::Error *_Nullable error);

    ~OCIPackage() final;

    bool isValid() const;

    bool isMountable() const override;

    LIBRALF_NS::Package::Format format() const override;

    ssize_t size() const override;

    ssize_t unpackedSize() const override;

    bool verify(LIBRALF_NS::Error *_Nullable error) override;

    LIBRALF_NS::Result<std::unique_ptr<LIBRALF_NS::IPackageMountImpl>> mount(const std::filesystem::path &mountPoint,
                                                                             LIBRALF_NS::MountFlags flags) override;

    std::shared_ptr<LIBRALF_NS::IPackageMetaDataImpl> metaData(LIBRALF_NS::Error *_Nullable error) override;

    std::list<LIBRALF_NS::Certificate> signingCertificates(LIBRALF_NS::Error *_Nullable error) override;

    std::unique_ptr<LIBRALF_NS::IPackageReaderImpl> createReader(LIBRALF_NS::Error *_Nullable error) override;

    std::unique_ptr<LIBRALF_NS::IPackageAuxMetaDataImpl> auxMetaDataFile(std::string_view mediaType, size_t index,
                                                                         LIBRALF_NS::Error *_Nullable error) override;

    LIBRALF_NS::Result<size_t> auxMetaDataFileCount(std::string_view mediaType) override;

    LIBRALF_NS::Result<std::set<std::string>> auxMetaDataKeys() override;

    size_t maxExtractionBytes() const override;

    void setMaxExtractionBytes(size_t maxTotalSize) override;

    size_t maxExtractionEntries() const override;

    void setMaxExtractionEntries(size_t maxFileCount) override;

private:
    LIBRALF_NS::Result<std::vector<uint8_t>> readBlob(const std::string &sha256, uint64_t size) const;

    LIBRALF_NS::Result<std::unique_ptr<IOCIFileReader>> getBlobReader(const std::string &sha256) const;

    LIBRALF_NS::Result<> buildContentsTree();

    static LIBRALF_NS::Result<> checkOciLayoutFile(const std::vector<uint8_t> &data);

    static LIBRALF_NS::Result<std::list<OCIDescriptor>> processIndexFile(const std::vector<uint8_t> &data);

    LIBRALF_NS::Result<> processManifest(const OCIDescriptor &manifest);

    static bool isPackageDataManifest(const OCIDescriptor &config, const std::vector<OCIDescriptor> &layers);

    static bool isSignatureManifest(const OCIDescriptor &config, const std::vector<OCIDescriptor> &layers);

    LIBRALF_NS::Result<> readAndVerifySignature(const LIBRALF_NS::VerificationBundle &bundle,
                                                LIBRALF_NS::Package::OpenFlags flags);

    LIBRALF_NS::Result<> verifySignaturePayload(const std::vector<uint8_t> &signedBlob);

    LIBRALF_NS::Result<> calcAndCheckBlobDigest(const OCIDescriptor &descriptor);

    struct DmVerityAnnotations
    {
        std::vector<uint8_t> rootHash;
        std::vector<uint8_t> salt;
        uint64_t hashesOffset = 0;
    };

    struct CryptoAnnotations
    {
        std::string jwe;
        std::string type;
        int keySize;
    };

    struct CryptoVerityAnnotations
    {
        CryptoAnnotations crypto;
        DmVerityAnnotations verity;
    };

    static LIBRALF_NS::Result<DmVerityAnnotations>
    getDmVerityAnnotations(const std::shared_ptr<const OCIDescriptor> &descriptor);

    static LIBRALF_NS::Result<CryptoAnnotations>
    getCryptoAnnotations(const std::shared_ptr<const OCIDescriptor> &descriptor);

    static LIBRALF_NS::Result<CryptoVerityAnnotations>
    getCryptoVerityAnnotations(const std::shared_ptr<const OCIDescriptor> &descriptor);

private:
    friend class OCIArchiveImageLayerReader;

    std::shared_ptr<IOCIBackingStore> m_backingStore;

    std::shared_ptr<entos::ralf::dmverity::IDmVerityMounter> m_dmVerityMounter;
    std::shared_ptr<entos::ralf::dmverity::ILuksMounter> m_luksMounter;

    mutable std::atomic<ssize_t> m_unpackedSize = -1;

    /// This is the digest of the manifest that contains the config and image layers, this is the thing that should
    /// be signed, as it means the config and image layers are also verified.
    std::string m_packageDataManifestDigest;

    /// The descriptor that refers to the package 'image' layer
    std::shared_ptr<const OCIDescriptor> m_packageImageDescriptor;

    /// The descriptor that refers to the package 'config'
    std::shared_ptr<const OCIDescriptor> m_packageConfigDescriptor;

    /// The descriptor that refers to the package 'signature' layer.  The signature manifest can have a config but
    /// it doesn't contain anything useful for us, so we ignore it.  So this is the signature descriptor which has
    /// the annotations and refers to the signed blob ... which then references the package data manifest.
    std::shared_ptr<const OCIDescriptor> m_signatureDescriptor;

    /// Set to true only if opened with a verification bundle and the signature was verified
    bool m_verifiedManifest = false;

    /// Any additional "layers" in the package manifest that are not the package image or config.  These are treated as
    /// auxiliary meta-data files, and can be read using auxMetaDataFile() method.
    std::list<std::shared_ptr<const OCIDescriptor>> m_otherImageLayerDescriptors;

    mutable std::mutex m_cachedDataLock;
    mutable std::shared_ptr<LIBRALF_NS::IPackageMetaDataImpl> m_metaData;
    std::list<LIBRALF_NS::Certificate> m_signingCerts;

    size_t m_maxExtractionBytes = SIZE_MAX;
    size_t m_maxExtractionEntries = SIZE_MAX;
};
