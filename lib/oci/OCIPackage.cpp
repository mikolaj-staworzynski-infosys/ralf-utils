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

#include "OCIPackage.h"
#include "OCIArchiveBackingStore.h"
#include "OCIArchiveImageLayerReader.h"
#include "OCIDescriptor.h"
#include "OCIDirBackingStore.h"
#include "OCIErofsImageLayerReader.h"
#include "OCIMediaTypes.h"
#include "OCIPackageMetaDataImpl.h"
#include "OCIUtils.h"
#include "core/Base64.h"
#include "core/CryptoDigestBuilder.h"
#include "core/DigitalSignature.h"
#include "core/LogMacros.h"
#include "core/PackageAuxMetaDataImpl.h"
#include "dm-verity/IDmVerityMounter.h"
#include "luks/ILuksMounter.h"
#if defined(__linux__)
#    include "dm-verity/DmVerityMounterLinux.h"
#    include "luks/LuksMounterLinux.h"
#endif

#include <nlohmann/json.hpp>

#include <climits>
#include <cstring>
#include <regex>
#include <sstream>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(LIBRALF_NS)
using namespace LIBRALF_NS;
#endif

using namespace entos::ralf::dmverity;

/// The required name of the oci-layout file in the package
#define OCI_LAYOUT_FILE_NAME "oci-layout"

/// The maximum size allowed for the oci-layout file
#define OCI_LAYOUT_FILE_MAX_SIZE (64 * 1024)

/// The required name of the index file in the OCI package
#define OCI_INDEX_FILE_NAME "index.json"

/// The maximum size allowed for the index.json file
#define OCI_INDEX_FILE_MAX_SIZE (1 * 1024 * 1024)

/// The maximum size allowed for a manifest JSON file
#define OCI_MANIFEST_FILE_MAX_SIZE (4ULL * 1024 * 1024)

/// The required mediaType of the OCI manifest descriptor
#define OCI_MANIFEST_MEDIA_TYPE "application/vnd.oci.image.manifest.v1+json"

/// The mediaType for our package configuration
#define PACKAGE_CONFIG_MEDIA_TYPE "application/vnd.rdk.package.config.v1+json"

/// The maximum size allowed for the package configuration JSON file
#define PACKAGE_CONFIG_FILE_MAX_SIZE (4ULL * 1024 * 1024)

/// The maximum size of the signed blob
#define SIGNED_PAYLOAD_MAX_SIZE (1ULL * 1024 * 1024)

/// The minimum size of an EROFS image, this is basically just the size of the superblock.  If an empty EROFS image
/// is created it will just be a superblock as there are no files.
#define MIN_EROFS_IMAGE_SIZE (4 * 1024)

/// The maximum size of an EROFS image, this is just a sanity check to prevent trying to read a very large file.
#define MAX_EROFS_IMAGE_SIZE (2ULL * 1024 * 1024 * 1024)

/// The minimum size of a dm-verity hash tree, this is the size of the superblock. If the actual file system is less
/// than the data block size then there is no hash tree and the root hash is just the hash of the single data block.
#define MIN_DMVERITY_IMAGE_SIZE (4 * 1024)

/// Set a maximum size for the auxiliary meta data files in the package.  This is just a sanity check to prevent
/// trying to read a very large file, since we copy it all into memory.
#define MAX_AUX_META_DATA_SIZE (4ULL * 1024 * 1024)

// -------------------------------------------------------------------------
/*!
    Attempts to open the package with initial basic signature check.

*/
std::unique_ptr<OCIPackage> OCIPackage::open(int packageFd, const std::optional<VerificationBundle> &bundle,
                                             Package::OpenFlags flags, Error *_Nullable error)
{
    auto backingStore = OCIArchiveBackingStore::open(packageFd, true);
    if (!backingStore)
    {
        if (error)
            *error = backingStore.error();

        return nullptr;
    }

    return open(backingStore.value(), bundle, flags, error);
}

// -------------------------------------------------------------------------
/*!
    Attempts to open the package with optional verification, using the
    supplied archive reader factory to create the archive reader objects.

*/
std::unique_ptr<OCIPackage> OCIPackage::open(std::shared_ptr<IOCIBackingStore> backingStore,
                                             const std::optional<LIBRALF_NS::VerificationBundle> &bundle,
                                             LIBRALF_NS::Package::OpenFlags flags, LIBRALF_NS::Error *_Nullable error)
{
    // Create mount handlers if on Linux.
    std::shared_ptr<IDmVerityMounter> dmVerityMounter;
    std::shared_ptr<ILuksMounter> luksMounter;
#if defined(__linux__)
    dmVerityMounter = std::make_shared<DmVerityMounterLinux>();
    luksMounter = std::make_shared<LuksMounterLinux>();
#endif

    // Create a wrapper on the package
    auto package = std::make_unique<OCIPackage>(std::move(backingStore), std::move(dmVerityMounter),
                                                std::move(luksMounter), error);
    if (!package || !package->isValid())
        return nullptr;

    // If a bundle was supplied then verify the signature of the package, this doesn't check the digests
    // of the files in the package, it just verifies the signature blob.  When the blobs are read
    // they'll have their digests checked ... or if verify() is called.
    if (bundle)
    {
        auto result = package->readAndVerifySignature(bundle.value(), flags);
        if (!result)
        {
            if (error)
                *error = result.error();

            return nullptr;
        }
    }

    return package;
}

// -------------------------------------------------------------------------
/*!
    \internal

    Constructs the package object by dup'ing the file descriptor and storing
    the size of the package.
*/
OCIPackage::OCIPackage(std::shared_ptr<IOCIBackingStore> &&backingStore,
                       std::shared_ptr<IDmVerityMounter> &&dmVerityMounter,
                       std::shared_ptr<ILuksMounter> &&luksMounter, LIBRALF_NS::Error *_Nullable error)
    : m_backingStore(std::move(backingStore))
    , m_dmVerityMounter(std::move(dmVerityMounter))
    , m_luksMounter(std::move(luksMounter))
{
    // Build the basic tree of contents in the package
    auto result = buildContentsTree();
    if (!result)
    {
        if (error)
            *error = result.error();

        m_backingStore.reset();
    }
}

OCIPackage::~OCIPackage() // NOLINT(modernize-use-equals-default)
{
}

// -------------------------------------------------------------------------
/*!
    \internal

    Reads a blob from the package.  Blobs are stored in the "blobs/sha256"
    directory, and their file names are the \a sha256 hash hex string.

    This function also checks that the sha256 hash of the blob matches
    the given \a sha256 hash.  If the blob is larger than \a maxSize then an
    error is returned.

    FIXME: This is inefficient as it opens the archive fresh each time to
    find the blob.
 */
Result<std::vector<uint8_t>> OCIPackage::readBlob(const std::string &sha256, uint64_t size) const
{
    static const std::filesystem::path blobsPath = "blobs/sha256";

    // Sanity check the sha256 string is valid
    if (!validateSha256Digest(sha256))
        return Error(ErrorCode::PackageContentsInvalid, "Invalid sha256 hash");

    // Attempt to read the blob from the package
    auto content = m_backingStore->readFile(blobsPath / sha256, size);
    if (!content)
        return content;

    // Check the size of the blob matches the expected size
    if (content.value().size() != size)
        return Error(ErrorCode::PackageFileTooLarge, "Invalid blob size");

    // Check the sha256 hash of the blob matches the given sha256 hash
    const auto actualSha256 = CryptoDigestBuilder::digest(CryptoDigestBuilder::Algorithm::Sha256, content.value());
    if (actualSha256 != hexStringToBytes(sha256))
        return Error::format(ErrorCode::PackageContentsInvalid, "Blob digest does not match signed digest for '%s'",
                             sha256.c_str());

    return content;
}

// -------------------------------------------------------------------------
/*!
    \internal

    Creates a reader object for a blob within the OCI package.

    This is just a helper that prefixes the standard "blobs/sha256" directory
    to the path.

 */
Result<std::unique_ptr<IOCIFileReader>> OCIPackage::getBlobReader(const std::string &sha256) const
{
    static const std::filesystem::path blobsPath = "blobs/sha256";

    // Sanity check the sha256 string is valid
    if (!validateSha256Digest(sha256))
        return Error(ErrorCode::PackageContentsInvalid, "Invalid sha256 hash");

    return m_backingStore->getFile(blobsPath / sha256);
}

// -------------------------------------------------------------------------
/*!
    \internal

    Builds the contents tree of the package.

 */
Result<> OCIPackage::buildContentsTree()
{
    // Read and validate the oci-layout file
    auto ociLayout = m_backingStore->readFile(OCI_LAYOUT_FILE_NAME, OCI_LAYOUT_FILE_MAX_SIZE);
    if (!ociLayout)
        return ociLayout.error();

    auto result = checkOciLayoutFile(ociLayout.value());
    if (!result)
        return result;

    // Read and processes the index.json file
    auto indexJson = m_backingStore->readFile(OCI_INDEX_FILE_NAME, OCI_INDEX_FILE_MAX_SIZE);
    if (!indexJson)
        return indexJson.error();

    auto manifests = processIndexFile(indexJson.value());
    if (!manifests)
        return manifests.error();

    // Now process all the manifest files, this will fetch their contents from the tarball if don't have already
    // and will verify we have the right blobs needed
    for (const auto &manifest : manifests.value())
    {
        result = processManifest(manifest);
        if (!result)
            return result;
    }

    // Check that at a minimum we have a blob for the config and app data, the signature is likely to also be
    // required, but that is only checked if supplied with a bundle to verify the signature against
    if (m_packageDataManifestDigest.empty() || !m_packageImageDescriptor || !m_packageConfigDescriptor)
    {
        return Error(ErrorCode::PackageContentsInvalid, "Missing required blob(s) in package");
    }

    // Sanity check the size of the package config file
    if (m_packageConfigDescriptor->size() > PACKAGE_CONFIG_FILE_MAX_SIZE)
    {
        return Error::format(ErrorCode::PackageContentsInvalid, "Package config file is too large - %" PRIu64 " bytes",
                             m_packageConfigDescriptor->size());
    }

    return Ok();
}

// -------------------------------------------------------------------------
/*!
    \internal
    \static

    Checks that the "oci-layout" file is valid and contains the expected json.

 */
Result<> OCIPackage::checkOciLayoutFile(const std::vector<uint8_t> &data)
{
    const auto root = nlohmann::json::parse(data, nullptr, false);
    if (!root.is_object())
        return Error(ErrorCode::PackageContentsInvalid, "Invalid oci-layout file - not a JSON object");

    static const nlohmann::json expected = { { "imageLayoutVersion", "1.0.0" } };
    if (root != expected)
        return Error(ErrorCode::PackageContentsInvalid, "Invalid oci-layout file - invalid structure or version");

    return Ok();
}

// -------------------------------------------------------------------------
/*!
    \internal
    \static

    Processes the `index.json` file and populates the manifests map with the
    all the manifest meta-data found in the file.

    An example index.json file:
    \code
        {
            "schemaVersion": 2,
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "sha256:4161227e2a40097d5e00150b6027e86ea78a03f3668d41cf240173dc9b199614",
                    "size": 469,
                    "annotations": {
                        "org.opencontainers.image.ref.name": "test"
                    }
                },
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "sha256:f85bf2af0b25c1e0774ecc283e192fddc4dafbb33ef5ec47a863c1f1880fc48f",
                    "size": 9299,
                    "annotations": {
                        "org.opencontainers.image.ref.name": "sha256-4161227e2a40097d5e00150b6027e86ea78a03f3668d41cf240173dc9b199614.sig"
                    }
                }
            ]
        }
    \endcode

 */
Result<std::list<OCIDescriptor>> OCIPackage::processIndexFile(const std::vector<uint8_t> &data)
{
    static const std::filesystem::path blobsPath = "blobs/sha256";
    std::list<OCIDescriptor> ociManifests;

    const auto root = nlohmann::json::parse(data, nullptr, false);
    if (!root.is_object())
        return Error(ErrorCode::PackageContentsInvalid, "Invalid index.json file - not a JSON object");

    // check the schema version
    const auto schemaVersion = root.find("schemaVersion");
    if (schemaVersion == root.end() || !schemaVersion->is_number_integer() || (*schemaVersion != 2))
        return Error(ErrorCode::PackageContentsInvalid, "Invalid index.json file - invalid schema version");

    // process the manifests array
    const auto manifests = root.find("manifests");
    if (manifests == root.end() || !manifests->is_array())
        return Error(ErrorCode::PackageContentsInvalid, "Invalid index.json file - invalid or missing manifests array");

    for (const auto &manifest : *manifests)
    {
        auto parsedManifest = OCIDescriptor::parse(manifest);
        if (!parsedManifest)
            return parsedManifest.error();

        ociManifests.emplace_back(std::move(parsedManifest.value()));
    }

    return ociManifests;
}

// -------------------------------------------------------------------------
/*!
    \internal

    Processes a manifest descriptor, by getting the manifest blob contents,
    parsing it and checking it.



    \see https://github.com/opencontainers/image-spec/blob/main/manifest.md
 */
Result<> OCIPackage::processManifest(const OCIDescriptor &manifest)
{
    // Check the manifest is a valid OCI manifest
    if (manifest.mediaType() != OCI_MANIFEST_MEDIA_TYPE)
    {
        return Error(ErrorCode::PackageContentsInvalid,
                     "Invalid index.json file - invalid mediaType for manifest entry in index.json");
    }

    // Check the manifest blob is a sensible size
    if (manifest.size() > OCI_MANIFEST_FILE_MAX_SIZE)
    {
        return Error::format(ErrorCode::PackageContentsInvalid, "Manifest blob size is too large - %" PRIu64 " bytes",
                             manifest.size());
    }

    // Read the manifest blob from the package
    auto blob = readBlob(manifest.digest(), manifest.size());
    if (!blob)
    {
        return blob.error();
    }

    // JSON parse the blob
    const auto root = nlohmann::json::parse(blob.value(), nullptr, false, true);
    if (!root.is_object())
    {
        return Error(ErrorCode::PackageContentsInvalid, "Invalid manifest blob - not a JSON object");
    }

    int schemaVersion = -1;
    std::string mediaType;
    std::optional<OCIDescriptor> config;
    std::vector<OCIDescriptor> layers;

    for (const auto &[key, value] : root.items())
    {
        if (key == "schemaVersion")
        {
            if (!value.is_number_integer())
                return Error(ErrorCode::PackageContentsInvalid,
                             "Invalid OCI manifest - 'schemaVersion' is not an integer");

            schemaVersion = value.get<int>();
        }
        else if (key == "mediaType")
        {
            if (!value.is_string())
                return Error(ErrorCode::PackageContentsInvalid, "Invalid OCI manifest - 'mediaType' is not a string");

            mediaType = value.get<std::string>();
        }
        else if (key == "config")
        {
            auto result = OCIDescriptor::parse(value);
            if (!result)
                return result.error();

            config = std::move(result.value());
        }
        else if (key == "layers")
        {
            if (!value.is_array())
                return Error(ErrorCode::PackageContentsInvalid, "Invalid OCI manifest - 'layers' is not an array");

            for (const auto &layer : value)
            {
                auto result = OCIDescriptor::parse(layer);
                if (!result)
                    return result.error();

                layers.emplace_back(std::move(result.value()));
            }
        }
    }

    if (schemaVersion != 2)
    {
        return Error(ErrorCode::PackageContentsInvalid, "Invalid OCI manifest - 'schemaVersion' is missing or not 2");
    }

    // 'mediaType' field is not mandatory, but if present it must be a string with manifest media type
    if (!mediaType.empty() && (mediaType != OCI_MANIFEST_MEDIA_TYPE))
    {
        return Error(ErrorCode::PackageContentsInvalid,
                     "Invalid OCI manifest - 'mediaType' is not a valid manifest media type");
    }

    // 'config' is required, but it can be empty
    if (!config)
    {
        return Error(ErrorCode::PackageContentsInvalid,
                     "Invalid OCI manifest - 'config' is missing or not a valid OCI descriptor");
    }

    // Check if the manifest is for the package data, which means the `config` has the correct media type at least
    // one of the layers is a known package layer
    if (isPackageDataManifest(config.value(), layers))
    {
        m_packageDataManifestDigest = manifest.digest();
        m_packageConfigDescriptor = std::make_shared<OCIDescriptor>(std::move(config.value()));

        for (auto &layer : layers)
        {
            if (layer.mediaType().find(PACKAGE_IMAGE_MEDIA_TYPE_PREFIX) == 0)
                m_packageImageDescriptor = std::make_shared<OCIDescriptor>(std::move(layer));
            else
                m_otherImageLayerDescriptors.emplace_back(std::make_shared<OCIDescriptor>(std::move(layer)));
        }
    }
    else if (isSignatureManifest(config.value(), layers))
    {
        for (auto &layer : layers)
        {
            if (layer.mediaType() == PACKAGE_SIGNATURE_MEDIA_TYPE)
                m_signatureDescriptor = std::make_shared<OCIDescriptor>(std::move(layer));
        }
    }

    return Ok();
}

bool OCIPackage::isPackageDataManifest(const OCIDescriptor &config, const std::vector<OCIDescriptor> &layers)
{
    // Check the config media type is the package config media type
    if (config.mediaType() != PACKAGE_CONFIG_MEDIA_TYPE)
        return false;

    // Check if any of the layers are a package layer
    for (const auto &layer : layers)
    {
        if (layer.mediaType().find(PACKAGE_IMAGE_MEDIA_TYPE_PREFIX) == 0)
            return true;
    }

    return false;
}

bool OCIPackage::isSignatureManifest(const OCIDescriptor &config, const std::vector<OCIDescriptor> &layers)
{
    // Don't care about the config for the signature manifest
    (void)config;

    // Check if any of the layers are a package layer
    for (const auto &layer : layers)
    {
        if (layer.mediaType() == PACKAGE_SIGNATURE_MEDIA_TYPE)
            return true;
    }

    return false;
}

// -------------------------------------------------------------------------
/*!
    \internal

    Here we process the signature descriptor.  This is actual the layer
    in the signature manifest that has the type `application/vnd.dev.cosign.simplesigning.v1+json`.

    It's important to note that at this point we have already read and checked
    the sha256 of the main package manifest; the signature is expected to cover
    this manifest. So this code will check the certificate signing chain against
    the verification bundle, and then check the signature against the signed data,
    and then check the signed data references the package data manifest.

    An example of the layer descriptor is:
    \code
        {
            "mediaType": "application/vnd.dev.cosign.simplesigning.v1+json",
            "size": 243,
            "digest": "sha256:f55379abf8de5f1abedab0cd5399c1a1c7a3d60636fe654e3f03779f8ed42fc4",
            "annotations": {
                "dev.cosignproject.cosign/signature": "R/E7xo8xv1O3uVQVqXNXDp8AXq ....",
                "dev.sigstore.cosign/certificate": "-----BEGIN CERTIFICATE-----\nMIIFhjCCA26gAwIBAgICEAAw ... ",
                "dev.sigstore.cosign/chain": "-----BEGIN CERTIFICATE-----\nMIIFRjCCAy6gAwIBAgIC ... "
        }
    \endcode

    Where the digest refers to the signed blob, that blob is a JSON object, refer
    to verifySignaturePayload() for more info.

    \see https://github.com/sigstore/cosign
 */
Result<> OCIPackage::readAndVerifySignature(const VerificationBundle &bundle, Package::OpenFlags flags)
{
    if (!m_signatureDescriptor)
        return Error(ErrorCode::PackageSignatureMissing, "Package doesn't have a signature descriptor");

    // Regex to remove newlines from the certificate chain
    static const std::regex newlineRegex("\\n");

    // Check the signature descriptor has the required annotations
    std::vector<uint8_t> signature;
    Certificate certificate;
    std::list<Certificate> certificateChain;
    for (const auto &[key, value] : m_signatureDescriptor->annotations())
    {
        if (key == COSIGN_ANNOTATION_SIGNATURE)
        {
            auto result = Base64::decode(value);
            if (!result)
                return Error(ErrorCode::PackageSignatureInvalid, "Invalid signature blob - not base64 encoded");

            signature = std::move(result.value());
        }
        else if (key == COSIGN_ANNOTATION_SIGNING_CERTIFICATE)
        {
            auto result = Certificate::loadFromString(std::regex_replace(value, newlineRegex, "\n"));
            if (!result || !result.value().isValid())
                return Error(ErrorCode::PackageSignatureInvalid, "Invalid signing certificate - not a valid PEM");

            certificate = std::move(result.value());
        }
        else if (key == COSIGN_ANNOTATION_SIGNING_CERTIFICATE_CHAIN)
        {
            auto result = Certificate::loadFromStringMultiCerts(std::regex_replace(value, newlineRegex, "\n"));
            if (!result || result.value().empty())
                return Error(ErrorCode::PackageSignatureInvalid, "Invalid certificate chain");

            certificateChain = std::move(result.value());
        }
    }

    // Check we have both a signature chain and a signing certificate, the certificate chain is not strictly required
    // but everything we sign is likely to have one
    if (signature.empty())
        return Error(ErrorCode::PackageSignatureInvalid, "Missing signature blob");
    if (!certificate.isValid())
        return Error(ErrorCode::PackageSignatureInvalid, "Missing signing certificate");

    // Store the certificate chain even if it doesn't verify, it may help with debug for clients
    {
        std::lock_guard lock(m_cachedDataLock);

        m_signingCerts.clear();
        m_signingCerts.emplace_back(certificate);
        for (const auto &cert : certificateChain)
            m_signingCerts.emplace_back(cert);
    }

    // Set the verification options
    VerificationBundle::VerifyOptions options = VerificationBundle::VerifyOptions::None;
    if ((flags & Package::OpenFlags::CheckCertificateExpiry) == Package::OpenFlags::CheckCertificateExpiry)
        options |= VerificationBundle::VerifyOptions::CheckCertificateExpiry;

    // Verify the certificate chain against the verification bundle
    if (!bundle.verifyCertificate(certificate, certificateChain, options))
        return Error(ErrorCode::PackageSignatureInvalid, "Invalid signing certificate chain");

    // Check the signed blob is not excessively large
    if (m_signatureDescriptor->size() > SIGNED_PAYLOAD_MAX_SIZE)
        return Error(ErrorCode::PackageSignatureInvalid, "Signature payload too large");

    // Read the signed blob from the package, this is a JSON document that references the sha256 of the package data
    // manifest
    auto signedBlob = readBlob(m_signatureDescriptor->digest(), m_signatureDescriptor->size());
    if (!signedBlob)
        return Error(ErrorCode::PackageSignatureInvalid, "Missing or invalid signature blob");

    // We then use the certificate to verify the signature of the signed blob
    DigitalSignature checker(DigitalSignature::Algorithm::Sha256);
    checker.update(signedBlob.value());
    if (!checker.verify(certificate, signature))
        return Error(ErrorCode::PackageSignatureInvalid, "Invalid signature");

    // Now the signed blob is verified we need to check the contents of the signed blob, it should be a
    // JSON document that meets the requirements in https://github.com/containers/image/blob/main/docs/containers-signature.5.md
    auto result = verifySignaturePayload(signedBlob.value());
    if (!result)
        return result;

    // Everything is ok
    m_verifiedManifest = true;

    return Ok();
}

// -------------------------------------------------------------------------
/*!
    \internal

    Verifies the contents of the signed blob.  The signed blob is a JSON document
    with a format that looks like:
    \code
    {
        "critical": {
            "type": "cosign container image signature",
            "image": {
                "docker-manifest-digest": "sha256:4161227e2a40097d5e00150b6027e86ea78a03f3668d41cf240173dc9b199614"
            },
            "identity": {
                "docker-reference": "my.cool.app:1.0"
            }
        },
        "optional": null
    }
    \endcode

    The important bit is the 'docker-manifest-digest' which should match
    the sha256 of the package data manifest, if it doesn't then the signature
    doesn't cover the package data manifest and we can't trust it.

    The container signing specification is strict on the exact contents of the
    JSON, however the cosign tool doesn't exactly follow the spec.  So maybe
    in the future we'll define a variant of the spec that is more in keeping
    with our usage ... but still would like to keep compatibility with the
    OCI distribution spec.

    \see https://github.com/containers/image/blob/main/docs/containers-signature.5.md
    \see https://www.redhat.com/en/blog/container-image-signing

 */
Result<> OCIPackage::verifySignaturePayload(const std::vector<uint8_t> &signedBlob)
{
    const auto root = nlohmann::json::parse(signedBlob, nullptr, false);
    if (!root.is_object())
        return Error(ErrorCode::PackageSignatureInvalid, "Invalid signature payload - not a JSON object");

    // Process the critical section of the JSON
    auto critical = root.find("critical");
    if (critical == root.end() || !critical->is_object())
        return Error(ErrorCode::PackageSignatureInvalid, "Invalid signature payload - missing critical section");

    unsigned flags = 0;
    enum : unsigned
    {
        VerifiedType = 1,
        VerifiedIdentity = 2,
        VerifiedManifestDigest = 4
    };

    try
    {
        // flatten the json object to remove any nested objects, this makes it easier to work with and check
        // that no extra unknown fields are present
        const auto flattened = critical->flatten();
        for (const auto &[key, value] : flattened.items())
        {
            if (key == "/type")
            {
                if (!value.is_string() || (value != "cosign container image signature"))
                    return Error(ErrorCode::PackageSignatureInvalid, "Invalid signature payload - invalid type");

                flags |= VerifiedType;
            }
            else if (key == "/identity/docker-reference")
            {
                if (!value.is_string())
                    return Error(ErrorCode::PackageSignatureInvalid,
                                 "Invalid signature payload - invalid critical.identity.docker-reference value");

                // For now don't care what the docker-reference is...
                flags |= VerifiedIdentity;
            }
            else if (key == "/image/docker-manifest-digest")
            {
                if (!value.is_string())
                    return Error(ErrorCode::PackageSignatureInvalid,
                                 "Invalid signature payload - invalid critical.image.docker-manifest-digest value");

                // Check the digest string is valid
                const auto manifestDigest = validateDigest(value.get<std::string>());
                if (!manifestDigest)
                    return Error(ErrorCode::PackageSignatureInvalid,
                                 "Invalid signature payload - critical.image.docker-manifest-digest is malformed");

                // This is the important bit, check the digest matches the package data manifest
                if (manifestDigest.value() != m_packageDataManifestDigest)
                    return Error(ErrorCode::PackageSignatureInvalid,
                                 "Invalid signature payload - critical.image.docker-manifest-digest doesn't match "
                                 "package data manifest");

                flags |= VerifiedManifestDigest;
            }
            else
            {
                return Error(ErrorCode::PackageSignatureInvalid,
                             "Invalid signature payload - unknown key in critical section");
            }
        }
    }
    catch (const nlohmann::json::exception &e)
    {
        return Error(ErrorCode::PackageSignatureInvalid, "Invalid signature payload - JSON parse error");
    }

    // Ignore the optional section for now

    // Check we have verified the 3 required parts of the signature payload
    if (flags != (VerifiedType | VerifiedIdentity | VerifiedManifestDigest))
        return Error(ErrorCode::PackageSignatureInvalid, "Invalid signature payload - missing required field(s)");

    // Otherwise we're all good
    return Ok();
}

Package::Format OCIPackage::format() const
{
    return Package::Format::Ralf;
}

bool OCIPackage::isValid() const
{
    return !m_packageDataManifestDigest.empty() && m_packageConfigDescriptor && m_packageImageDescriptor;
}

bool OCIPackage::isMountable() const
{
    if (!m_packageImageDescriptor)
        return false;

    if (!m_backingStore->supportsMountableFiles())
        return false;

    const auto &mediaType = m_packageImageDescriptor->mediaType();
    if ((mediaType != PACKAGE_IMAGE_MEDIA_TYPE_PACKAGE_CONTENT_EROFS) &&
        (mediaType != PACKAGE_IMAGE_MEDIA_TYPE_PACKAGE_CONTENT_EROFS_ENCRYPTED))
    {
        return false;
    }

    // ... as long as the image layer data is not compressed and aligned
    static const std::filesystem::path blobsPath = "blobs/sha256";
    auto imagePath = blobsPath / m_packageImageDescriptor->digest();

    const auto mappableFile = m_backingStore->getMappableFile(imagePath);
    return mappableFile && mappableFile.value()->isAligned();
}

ssize_t OCIPackage::size() const
{
    return static_cast<ssize_t>(m_backingStore->size());
}

ssize_t OCIPackage::unpackedSize() const
{
    // FIXME: This should be the size of the unpacked package, get from annotation ?
    return -1;
}

// -------------------------------------------------------------------------
/*!
    Performs a full signature verification of the package.  This doesn't
    check the contents of the config or the image, just that sha256 digests
    match the values in the signed blob.

 */
bool OCIPackage::verify(LIBRALF_NS::Error *_Nullable error)
{
    // First check is that the package was opened with a bundle to verify
    if (!m_verifiedManifest)
    {
        if (error)
            error->assign(ErrorCode::NotSupported, "Package wasn't opened with a verification bundle");

        return false;
    }

    // Check we have the required descriptors
    if (!m_signatureDescriptor || !m_packageConfigDescriptor || !m_packageImageDescriptor)
    {
        if (error)
        {
            if (!m_signatureDescriptor)
                *error = Error(ErrorCode::PackageSignatureInvalid, "Package does not contain a signature");
            else
                *error = Error(ErrorCode::PackageSignatureInvalid, "Package signature does not match package data");
        }

        return false;
    }

    // So we've verified the signature of the manifest, but not that actual data store in the image layers or
    // config, so we do that now
    auto result = calcAndCheckBlobDigest(*m_packageConfigDescriptor);
    if (!result)
    {
        if (error)
            *error = Error(ErrorCode::PackageSignatureInvalid, "Package config digest mismatch");

        return false;
    }

    result = calcAndCheckBlobDigest(*m_packageImageDescriptor);
    if (!result)
    {
        if (error)
            *error = Error(ErrorCode::PackageSignatureInvalid, "Package image digest mismatch");

        return false;
    }

    for (const auto &layer : m_otherImageLayerDescriptors)
    {
        result = calcAndCheckBlobDigest(*layer);
        if (!result)
        {
            if (error)
                *error = Error(ErrorCode::PackageSignatureInvalid, "Package aux metadata file digest mismatch");

            return false;
        }
    }

    return true;
}

// -------------------------------------------------------------------------
/*!
    \internal

    Helper function to read a blob from the OCI package and calculate it's
    digest, comparing it to the expected size and digest store in the
    \a descriptor.

 */
Result<> OCIPackage::calcAndCheckBlobDigest(const OCIDescriptor &descriptor)
{
    auto result = getBlobReader(descriptor.digest());
    if (!result)
        return result.error();

    auto reader = std::move(result.value());

    CryptoDigestBuilder digest(CryptoDigestBuilder::Algorithm::Sha256);

    uint8_t buffer[4096];
    uint64_t totalRead = 0;

    const uint64_t expectedBlobSize = reader->size();

    while (true)
    {
        const ssize_t bytesRead = reader->read(buffer, sizeof(buffer));
        if (bytesRead == 0)
            break;
        else if (bytesRead < 0)
            return Error(ErrorCode::PackageContentsInvalid, "Failed to read blob data");

        digest.update(buffer, bytesRead);
        totalRead += bytesRead;

        if (totalRead > expectedBlobSize)
            return Error(ErrorCode::PackageContentsInvalid, "Blob size exceeds expected size");
    }

    if (totalRead != expectedBlobSize)
        return Error(ErrorCode::PackageContentsInvalid, "Blob size mismatch");

    const auto expectedSha256 = hexStringToBytes(descriptor.digest());
    const auto actualSha256 = digest.finalise();
    if (actualSha256 != expectedSha256)
        return Error(ErrorCode::PackageContentsInvalid, "Blob digest mismatch");

    return Ok();
}

// -------------------------------------------------------------------------
/*!
    \internal
    \static

    Given an OCI descriptor, this method will attempt to get the dm-verity
    annotations from it.  It will perform some basic checks to ensure the
    descriptor is valid and has the expected annotations for dm-verity.

    The descriptor on a erfos+dmverity image layer should look something like this:

    \code
        {
            "mediaType": "application/vnd.rdk.package.content.layer.v1.erofs+dmverity",
            "digest": "sha256:123
            "size": 1234567,
            "annotations": {
                "org.rdk.package.content.dmverity.roothash": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                "org.rdk.package.content.dmverity.salt": "1234567890abcdef1234567890abcdef",
                "org.rdk.package.content.dmverity.offset": "123456"
            }
        }
    \endcode

 */
Result<OCIPackage::DmVerityAnnotations>
OCIPackage::getDmVerityAnnotations(const std::shared_ptr<const OCIDescriptor> &descriptor)
{
    // Check the media type is the expected one for an EROFS image layer.
    // The dm-verity descriptor is the base integrity layer and the LUKS-over-dm-verity variant is detected as an
    // independent media type that still carries the same dm-verity annotations.
    if (!descriptor ||
        ((descriptor->mediaType() != PACKAGE_IMAGE_MEDIA_TYPE_PACKAGE_CONTENT_EROFS) &&
         (descriptor->mediaType() != PACKAGE_IMAGE_MEDIA_TYPE_PACKAGE_CONTENT_EROFS_ENCRYPTED)))
    {
        return Error(ErrorCode::PackageMountInvalid, "Package image layer is doesn't have erfos+dmverity media type");
    }

    // Get the annotations from the image descriptor, this should contain the dm-verity root hash
    DmVerityAnnotations details;
    details.hashesOffset = UINT64_MAX;

    for (const auto &[key, value] : descriptor->annotations())
    {
        if (key == PACKAGE_ANNOTATION_DMVERITY_ROOTHASH)
        {
            details.rootHash = hexStringToBytes(value);
        }
        else if (key == PACKAGE_ANNOTATION_DMVERITY_SALT)
        {
            details.salt = hexStringToBytes(value);
        }
        else if (key == PACKAGE_ANNOTATION_DMVERITY_OFFSET)
        {
            details.hashesOffset = strtoull(value.c_str(), nullptr, 10);
        }
    }

    // Currently we require that dm-verity is used when mounting the image, so its an error if the root hash is not
    // present or the offset is missing.  The salt is optional but is expected to be present.
    if (details.rootHash.size() != 32)
    {
        return Error(ErrorCode::PackageMountInvalid,
                     "Package image layer is missing dm-verity root hash or it's invalid");
    }
    if ((details.hashesOffset < MIN_EROFS_IMAGE_SIZE) || (details.hashesOffset > MAX_EROFS_IMAGE_SIZE))
    {
        return Error(ErrorCode::PackageMountInvalid, "Package image layer dm-verity offset is missing or invalid");
    }
    if (details.hashesOffset > (descriptor->size() - MIN_DMVERITY_IMAGE_SIZE))
    {
        return Error(ErrorCode::PackageMountInvalid, "Package image layer dm-verity offset has invalid value");
    }

    // Salt is optional, but if present it should be less than 256 bytes
    if (details.salt.size() > 255)
    {
        return Error(ErrorCode::PackageMountInvalid, "Package image layer dm-verity salt is too large");
    }

    return details;
}

Result<OCIPackage::CryptoAnnotations>
OCIPackage::getCryptoAnnotations(const std::shared_ptr<const OCIDescriptor> &descriptor)
{
    CryptoAnnotations details;
    details.keySize = 512;
    details.type = "luks2";
    details.jwe = "";
    for (const auto &[key, value] : descriptor->annotations())
    {
        if (key == PACKAGE_ANNOTATION_CRYPT_TYPE)
        {
            details.type = value;
        }
        else if (key == PACKAGE_ANNOTATION_CRYPT_KEYSIZE)
        {
            details.keySize = std::strtoul(value.c_str(), nullptr, 10);
        }
        else if (key == PACKAGE_ANNOTATION_CRYPT_JWE_KEY)
        {
            details.jwe = value;
        }
    }

    // A JWE block is completely mandatory for an encrypted image layout path
    if (descriptor->mediaType() == PACKAGE_IMAGE_MEDIA_TYPE_PACKAGE_CONTENT_EROFS_ENCRYPTED && details.jwe.empty())
    {
        return Error(ErrorCode::PackageMountInvalid, "Encrypted image layer is missing required JWE authorization block");
    }

    return details;
}

Result<OCIPackage::CryptoVerityAnnotations>
OCIPackage::getCryptoVerityAnnotations(const std::shared_ptr<const OCIDescriptor> &descriptor)
{
    CryptoVerityAnnotations details;

    auto verityResult = OCIPackage::getDmVerityAnnotations(descriptor);
    if (!verityResult)
    {
        return verityResult.error();
    }
    auto cryptoResult = OCIPackage::getCryptoAnnotations(descriptor);
    if (!cryptoResult)
    {
        return cryptoResult.error();
    }

    details.verity = std::move(verityResult.value());
    details.crypto = std::move(cryptoResult.value());
    return details;
}

// -------------------------------------------------------------------------
/*!
    For OCI package we try and support mounting the package contents if the
    image layer contains an EROFS image layer.

    It is expected that if the image layer is an EROFS image, then it will
    have a dm-verity hash tree and the root hash would have been supplied in
    the signed JSON layer descriptor.  If the package was opened with a
    verification bundle and no root hash was supplied then this method
    will fail - we don't want to support mounting images with no dm-verity
    protection, if the caller wants to do that then they should open the
    package without a verification bundle.

    Note it is expected the mount point is an existing directory, if not
    then this method will fail with an error.

 */
Result<std::unique_ptr<IPackageMountImpl>> OCIPackage::mount(const std::filesystem::path &mountPoint, MountFlags flags)
{
    // Check if the package is mountable, this is a simple check that the package is valid and has an image layer
    // with the media type of PACKAGE_IMAGE_MEDIA_TYPE_PACKAGE_CONTENT_EROFS or PACKAGE_IMAGE_MEDIA_TYPE_PACKAGE_CONTENT_EROFS_ENCRYPTED.
    if (!isMountable())
    {
        return Error(ErrorCode::PackageMountInvalid, "Package is not mountable");
    }

    // Although not strictly required, we expect the package metadata to have been parsed (and signature checked) before
    // attempting to mount the package
    const auto metaDataPtr = metaData(nullptr);
    if (!metaDataPtr)
    {
        return Error(ErrorCode::PackageMountInvalid, "Package metadata is not available");
    }

    // Sanity check the mount point is a directory
    if (!std::filesystem::is_directory(mountPoint))
    {
        return Error(ErrorCode::PackageMountInvalid, "Mount point is not an existing directory");
    }

    // Parse the media type first so the code can split the plain dm-verity path from the dedicated encrypted/LUKS2 path.
    const auto mediaType = m_packageImageDescriptor->mediaType();
    const bool encrypted = (mediaType == PACKAGE_IMAGE_MEDIA_TYPE_PACKAGE_CONTENT_EROFS_ENCRYPTED);

    if (encrypted)
    {
        logInfo("mounting encrypted package");
        // This path intentionally stays separate from the existing dm-verity mount path. It is the entry point for the
        // LUKS2-over-dm-verity layout, where the EROFS payload is wrapped inside the LUKS2 container and should be
        // mounted by the dedicated LUKS2/mapped-device handler rather than by the plain dm-verity loopback mount logic.
        if (!m_luksMounter)
        {
            return Error(ErrorCode::NotSupported,
                         "Library doesn't support mounting encrypted packages on this platform, or library built without encrypted mount support enabled");
        }

        auto cryptoVerityAnnotations = getCryptoVerityAnnotations(m_packageImageDescriptor);
        if (!cryptoVerityAnnotations)
        {
            logError("cannot get crypto annotations");
            return cryptoVerityAnnotations.error();
        }

        static const std::filesystem::path blobsPath = "blobs/sha256";
        auto imagePath = blobsPath / m_packageImageDescriptor->digest();
        logInfo("Encrypted package at: %s", imagePath.c_str());
        auto result = m_backingStore->getMappableFile(imagePath);
        if (!result)
        {
            logError("Encrypted package at: %s not mappable", imagePath.c_str());
            return Error::format(ErrorCode::PackageMountInvalid, "Encrypted package image layer is not mountable due to %s",
                                 result.error().what());
        }

        auto mountableBlob = std::move(result.value());
        if (!mountableBlob->isAligned())
        {
            logError("Encrypted package at: %s not aligned", imagePath.c_str());
            return Error::format(ErrorCode::PackageContentsInvalid,
                                 "Encrypted package image layer entry is not aligned, cannot mount");
        }

        // The encrypted path is now validated by the dedicated LUKS mounter itself, rather than by adapting the
        // dm-verity mounter interface to a second meaning.
        logInfo("mountable blob spanning vector in zip: %" PRIu64 " %" PRIu64 "", mountableBlob->offset(), mountableBlob->size());
        const ILuksMounter::FileRange completeLuksRange = { mountableBlob->offset(), mountableBlob->size()};
        const ILuksMounter::FileRange hashRange = {cryptoVerityAnnotations->verity.hashesOffset, 0}; // size - we will calculate that in mount after having decrypted mount
        // TODO: some checkImageFile
        auto startTime = std::chrono::steady_clock::now();
        auto mount = m_luksMounter->mount(metaDataPtr->id(), ILuksMounter::FileSystemType::Erofs,
                                          mountableBlob->fd(), mountPoint, completeLuksRange, hashRange,
                                          cryptoVerityAnnotations->verity.rootHash,
                                          cryptoVerityAnnotations->verity.salt,
                                          cryptoVerityAnnotations->crypto.jwe, flags);
        auto endTime = std::chrono::steady_clock::now();
        auto durationMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
        // keep printf to see that unconditionally
        printf("PERF: Total mounting package '%s' took %.2f ms (status: %s)\n", metaDataPtr->id().c_str(), durationMs, mount ? "SUCCESS" : "FAILED");

        return mount;
}

    logInfo("mounting clear package");
    // Check we have a mounter interface, we won't on non-linux platforms
    if (!m_dmVerityMounter)
    {
        return Error(ErrorCode::NotSupported, "Library doesn't support mounting packages on this platform, "
                                              "or library built without mount support enabled");
    }

    // Existing plain dm-verity path stays intact and continues to mount the original EROFS+dm-verity layout.
    auto annotations = getDmVerityAnnotations(m_packageImageDescriptor);
    if (!annotations)
    {
        return annotations.error();
    }

    static const std::filesystem::path blobsPath = "blobs/sha256";
    auto imagePath = blobsPath / m_packageImageDescriptor->digest();

    // This will return a file descriptor, file offset and size of the given blob, such that it could be mounted
    // (or memmapped).  This is not always possible, for example if the backing store is a compressed archive or if
    // stored in an archive that stores the file in non-contiguous blocks, then it won't be mountable.
    auto result = m_backingStore->getMappableFile(imagePath);
    if (!result)
    {
        return Error::format(ErrorCode::PackageMountInvalid, "Package image layer is not mountable due to %s",
                             result.error().what());
    }

    // Check the offset and size are aligned to the alignment boundary
    auto mountableBlob = std::move(result.value());
    if (!mountableBlob->isAligned())
    {
        return Error::format(ErrorCode::PackageContentsInvalid,
                             "Package image layer entry is not aligned, cannot mount");
    }

    // Sanity check the mappable blob size matches what was reported in the descriptor
    if (mountableBlob->size() != m_packageImageDescriptor->size())
    {
        return Error(ErrorCode::PackageMountInvalid,
                     "Package image layer is not mountable - size of the blob does not match descriptor");
    }

    // Check that the dm-verity offset is within the bounds of the image
    if ((mountableBlob->size() < (MIN_EROFS_IMAGE_SIZE + MIN_DMVERITY_IMAGE_SIZE)) ||
        (annotations->hashesOffset > (mountableBlob->size() - MIN_DMVERITY_IMAGE_SIZE)))
    {
        // If the size is too small then we can't mount it, so close the file descriptor and return an error
        // Note that the size check is to ensure that the dm-verity tree can fit in the image, so we can verify it
        // when mounting.
        return Error(ErrorCode::PackageMountInvalid,
                     "Package image layer is not mountable - size of offset is invalid");
    }

    // Finally we should have everything we need to create the mount object, we have
    //   - File descriptor to the thing to mount
    //   - Offset within the file to the start of the image to mount
    //   - Size of the image in the file to mount
    //   - The optional dm-verity root hash, salt and offset

    const IDmVerityMounter::FileRange dataRange = { mountableBlob->offset(), annotations->hashesOffset };
    const IDmVerityMounter::FileRange hashesRange = { mountableBlob->offset() + annotations->hashesOffset,
                                                      mountableBlob->size() - annotations->hashesOffset };

    auto mount = m_dmVerityMounter->mount(metaDataPtr->id(), IDmVerityMounter::FileSystemType::Erofs,
                                          mountableBlob->fd(), mountPoint, dataRange, hashesRange,
                                          annotations->rootHash, annotations->salt, flags);

    return mount;
}

// -------------------------------------------------------------------------
/*!
    Returns the package meta data, this is the parsed content of the config
    blob stored in the package.

    This is lazily loaded when first requested, and cached for later use.

    If the package was opened with a verification bundle then the meta data
    is signature checked prior to parsing it.

 */
std::shared_ptr<IPackageMetaDataImpl> OCIPackage::metaData(Error *_Nullable error)
{
    std::lock_guard locker(m_cachedDataLock);

    // Return cached value if have it
    if (m_metaData)
        return m_metaData;

    // If we have a descriptor then is guaranteed to be signature checked if the package was opened with a bundle
    if (!m_packageConfigDescriptor)
    {
        if (error)
            *error = Error(ErrorCode::PackageContentsInvalid, "Package does not contain a package config");

        return nullptr;
    }

    // readBlob reads the blob and checks the digest and size matches the content
    auto contents = readBlob(m_packageConfigDescriptor->digest(), m_packageConfigDescriptor->size());
    if (!contents)
    {
        if (error)
        {
            *error = Error::format(ErrorCode::PackageContentsInvalid, "Failed to read package config - %s",
                                   contents.error().what());
        }

        return nullptr;
    }

    // Parse the config blob
    auto metaData = OCIPackageMetaDataImpl::fromConfigJson(contents.value());
    if (!metaData)
    {
        if (error)
            *error = metaData.error();

        return nullptr;
    }

    m_metaData = std::move(metaData.value());
    return m_metaData;
}

// -------------------------------------------------------------------------
/*!
    Simply returns the signing certificate chain found during bundle verification.

    If the package was opened without a bundle then this will return an
    empty list.
 */
std::list<Certificate> OCIPackage::signingCertificates(Error *_Nullable error)
{
    std::lock_guard lock(m_cachedDataLock);
    return m_signingCerts;
}

// -------------------------------------------------------------------------
/*!
    Creates a new reader object for this package.  A reader is used to read
    the contents of the image layer stored in the package, it doesn't cover
    the package config or the signature.

    The OCIPackageReader is given the descriptor for the image layer, and
    a blob reader object that can be used to read the contents of the image layer.

    It's important to note that at this point the only thing we can guarantee
    is that if a verification bundle was supplied when opening the package, then
    the image descriptor object has been verified.  But the actual data that
    the descriptor points to has not been verified.
 */
std::unique_ptr<IPackageReaderImpl> OCIPackage::createReader(Error *_Nullable error)
{
    if (error)
        error->clear();

    if (!m_packageImageDescriptor)
    {
        if (error)
            *error = Error(ErrorCode::PackageContentsInvalid, "Package does not contain a package image");

        return nullptr;
    }

    // Check the mediaType in the package image descriptor, this determines the type of image reader to create.
    // The plain EROFS+dm-verity path uses the read-through dm-verity reader, while the encrypted media type is
    // intentionally not routed through this reader because it must be handled by the dedicated LUKS2 mount path.
    const std::string &mediaType = m_packageImageDescriptor->mediaType();
    if (mediaType == PACKAGE_IMAGE_MEDIA_TYPE_PACKAGE_CONTENT_EROFS)
    {
        // Get (and check) the dm-verity annotations from the image descriptor
        auto annotations = getDmVerityAnnotations(m_packageImageDescriptor);
        if (!annotations)
        {
            if (error)
                *error = annotations.error();
            return nullptr;
        }

        static const std::filesystem::path blobsPath = "blobs/sha256";
        auto imagePath = blobsPath / m_packageImageDescriptor->digest();

        // This will return a file descriptor, file offset and size of the given blob, such that it could be randomly
        // accessed.  This is not always possible, for example if the backing store is a compressed archive or if
        // stored in an archive that stores the file in non-contiguous blocks, then it won't be mountable.
        const auto mountableBlob = m_backingStore->getMappableFile(imagePath);
        if (!mountableBlob)
        {
            if (error)
            {
                *error = Error::format(ErrorCode::PackageMountInvalid,
                                       "Package EROFS image layer cannot be read due to %s",
                                       mountableBlob.error().what());
            }

            return nullptr;
        }

        // Create an EROFS image layer reader, this will read the files from the EROFS image and perform dm-verity
        // checks on all the data read from the image.
        return std::make_unique<OCIErofsImageLayerReader>(mountableBlob.value(), annotations->hashesOffset,
                                                          annotations->rootHash);
    }
    else if (mediaType == PACKAGE_IMAGE_MEDIA_TYPE_PACKAGE_CONTENT_EROFS_ENCRYPTED)
    {
        if (error)
        {
            *error = Error(ErrorCode::NotSupported,
                           "Encrypted EROFS layer requires the dedicated LUKS2 mount path and cannot be read by the dm-verity image reader");
        }

        return nullptr;
    }
    else if (mediaType.find(PACKAGE_IMAGE_MEDIA_TYPE_PREFIX) == 0)
    {
        // Create a blob reader for the package image layer, this will read the contents of the image layer
        auto blobReader = getBlobReader(m_packageImageDescriptor->digest());
        if (!blobReader)
        {
            if (error)
                *error = blobReader.error();

            return nullptr;
        }

        // Sanity check the size of the actual blob matches the size in the descriptor
        if (blobReader.value()->size() != static_cast<int64_t>(m_packageImageDescriptor->size()))
        {
            if (error)
                *error = Error(ErrorCode::PackageContentsInvalid, "Package image layer size mismatch");

            return nullptr;
        }

        // Create just an archive reader for the package image layer
        return std::make_unique<OCIArchiveImageLayerReader>(m_packageImageDescriptor, std::move(blobReader.value()));
    }
    else if (error)
    {
        *error = Error(ErrorCode::PackageContentsInvalid, "Package image descriptor has invalid media type");
    }

    return nullptr;
}

// -------------------------------------------------------------------------
/*!
    This API allows the caller to get additional "layer" files in the package
    using the media type and index.

    An example of an additional layer file is the appsecrets file.

    To make some of the tooling easier, we also allow the caller to get the
    raw JSON config file via this API by specifying the media type
    "application/vnd.rdk.package.config.v1+json" and index 0.
 */
std::unique_ptr<IPackageAuxMetaDataImpl> OCIPackage::auxMetaDataFile(std::string_view mediaType, size_t index,
                                                                     Error *_Nullable error)
{
    std::shared_ptr<const OCIDescriptor> descriptor;

    // Check if a request for the config file, this is a special case
    if (mediaType == PACKAGE_CONFIG_MEDIA_TYPE)
    {
        if (index != 0)
        {
            if (error)
                *error = Error(ErrorCode::PackageContentsInvalid, "Invalid index for package config file");

            return nullptr;
        }

        descriptor = m_packageConfigDescriptor;
    }
    else
    {
        // Try and find in the additional image layer descriptors
        size_t descCount = 0;
        for (const auto &desc : m_otherImageLayerDescriptors)
        {
            if (desc && (desc->mediaType() == mediaType))
            {
                if (index != descCount++)
                    continue;

                descriptor = desc;
                break;
            }
        }
    }

    if (!descriptor)
    {
        if (error)
            *error = Error::format(ErrorCode::PackageContentsInvalid,
                                   "No aux meta data file found for '%.*s' with index %zu'",
                                   static_cast<int>(mediaType.size()), mediaType.data(), index);

        return nullptr;
    }

    // Check the size of the descriptor is sensible, if not then return an error
    if (descriptor->size() > MAX_AUX_META_DATA_SIZE)
    {
        if (error)
            *error = Error(ErrorCode::PackageContentsInvalid, "Aux meta data size is too large");

        return nullptr;
    }

    // Read the blob for this descriptor
    auto blob = readBlob(descriptor->digest(), descriptor->size());
    if (!blob)
    {
        if (error)
            *error = blob.error();

        return nullptr;
    }

    // Create the aux meta data object
    return std::make_unique<PackageAuxMetaDataImpl>(mediaType, index, std::move(blob.value()), descriptor->annotations());
}

// -------------------------------------------------------------------------
/*!
    Returns the number of auxiliary meta data files for the given media type.

 */
Result<size_t> OCIPackage::auxMetaDataFileCount(std::string_view mediaType)
{
    if (mediaType == PACKAGE_CONFIG_MEDIA_TYPE)
    {
        return m_packageImageDescriptor ? 1 : 0;
    }
    else
    {
        size_t count = 0;
        for (const auto &desc : m_otherImageLayerDescriptors)
        {
            if (desc && (desc->mediaType() == mediaType))
                count++;
        }

        return count;
    }
}

Result<std::set<std::string>> OCIPackage::auxMetaDataKeys()
{
    std::set<std::string> keys;

    for (const auto &desc : m_otherImageLayerDescriptors)
    {
        if (desc)
            keys.insert(desc->mediaType());
    }

    return keys;
}

size_t OCIPackage::maxExtractionBytes() const
{
    return m_maxExtractionBytes;
}

void OCIPackage::setMaxExtractionBytes(size_t maxTotalSize)
{
    m_maxExtractionBytes = maxTotalSize;
}

size_t OCIPackage::maxExtractionEntries() const
{
    return m_maxExtractionEntries;
}

void OCIPackage::setMaxExtractionEntries(size_t maxFileCount)
{
    m_maxExtractionEntries = maxFileCount;
}
