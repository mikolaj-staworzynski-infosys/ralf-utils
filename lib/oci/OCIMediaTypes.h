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

/// The mediaType(s) for our package image layer
#define PACKAGE_IMAGE_MEDIA_TYPE_PREFIX "application/vnd.rdk.package.content.layer.v1."
#define PACKAGE_IMAGE_MEDIA_TYPE_PACKAGE_CONTENT_ZIP PACKAGE_IMAGE_MEDIA_TYPE_PREFIX "zip"
#define PACKAGE_IMAGE_MEDIA_TYPE_PACKAGE_CONTENT_TAR PACKAGE_IMAGE_MEDIA_TYPE_PREFIX "tar"
#define PACKAGE_IMAGE_MEDIA_TYPE_PACKAGE_CONTENT_TAR_GZIP PACKAGE_IMAGE_MEDIA_TYPE_PACKAGE_CONTENT_TAR "+gzip"
#define PACKAGE_IMAGE_MEDIA_TYPE_PACKAGE_CONTENT_TAR_ZSTD PACKAGE_IMAGE_MEDIA_TYPE_PACKAGE_CONTENT_TAR "+zstd"
#define PACKAGE_IMAGE_MEDIA_TYPE_PACKAGE_CONTENT_EROFS PACKAGE_IMAGE_MEDIA_TYPE_PREFIX "erofs+dmverity"
#define PACKAGE_IMAGE_MEDIA_TYPE_PACKAGE_CONTENT_EROFS_ENCRYPTED PACKAGE_IMAGE_MEDIA_TYPE_PREFIX "erofs+dmverity+encrypted"

/// The annotations keys for the dm-verity metadata
#define PACKAGE_ANNOTATION_DMVERITY_ROOTHASH "org.rdk.package.content.dmverity.roothash"
#define PACKAGE_ANNOTATION_DMVERITY_OFFSET "org.rdk.package.content.dmverity.offset"
#define PACKAGE_ANNOTATION_DMVERITY_SALT "org.rdk.package.content.dmverity.salt"

/// The annotations keys for the encryption metadata
#define PACKAGE_ANNOTATION_CRYPT_CIPHER "org.opencontainers.image.dmcrypt.cipher"
#define PACKAGE_ANNOTATION_CRYPT_KEYSIZE "org.opencontainers.image.dmcrypt.keysize"
#define PACKAGE_ANNOTATION_CRYPT_TYPE "org.opencontainers.image.dmcrypt.type"
#define PACKAGE_ANNOTATION_CRYPT_JWE_KEY "org.opencontainers.image.enc.keys.jwe"

/// The mediaType for our package signature layer
#define PACKAGE_SIGNATURE_MEDIA_TYPE "application/vnd.dev.cosign.simplesigning.v1+json"

/// The following are the signing annotations used by the cosign project
#define COSIGN_ANNOTATION_SIGNATURE "dev.cosignproject.cosign/signature"
#define COSIGN_ANNOTATION_SIGNING_CERTIFICATE "dev.sigstore.cosign/certificate"
#define COSIGN_ANNOTATION_SIGNING_CERTIFICATE_CHAIN "dev.sigstore.cosign/chain"
