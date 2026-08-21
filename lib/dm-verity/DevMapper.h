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

#include "DmVeritySuperBlock.h"
#include "Result.h"
#include "VersionNumber.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <list>
#include <string>
#include <string_view>
#include <vector>

struct dm_ioctl; // NOLINT

namespace entos::ralf::dmverity
{

    // -------------------------------------------------------------------------
    /*!
        \class DevMapper
        \brief Helper class to map / unmap volumes using the Linux devmapper.

        Traditionally you'd use the libdevmapper library to do this work, however
        that library is large and adds an extra dependency to the project. Given
        our use case is relatively simple, this class provides does the work
        the libdevmapper library does without the bells and whistles.


     */
    class DevMapper
    {
    public:
        DevMapper();
        ~DevMapper();

        DevMapper(const DevMapper &) = delete;
        DevMapper(DevMapper &&) = delete;

        DevMapper &operator=(const DevMapper &) = delete;
        DevMapper &operator=(DevMapper &&) = delete;

        bool isAvailable() const;

        LIBRALF_NS::VersionNumber version() const;

        LIBRALF_NS::Result<std::filesystem::path> mapWithVerity(int devFd, std::string_view name, std::string_view uuid,
                                                                uint64_t hashOffset, uint64_t dataSize,
                                                                const std::vector<uint8_t> &rootHash,
                                                                bool useUDevSync) const;

        LIBRALF_NS::Result<std::filesystem::path> mapWithCrypt(std::string_view devicePath, std::string_view name,
                                                               std::string_view uuid, uint64_t deviceSize,
                                                               const std::string &cipher, const std::string &keyType,
                                                               const std::string &keyDescription, size_t keySize,
                                                               uint64_t ivOffset, uint64_t dataOffset,
                                                               uint32_t sectorSize, bool useUDevSync) const;

        LIBRALF_NS::Result<> unmap(std::string_view name, std::string_view uuid, bool deferred = false) const;

        LIBRALF_NS::Result<std::string> mapStatus(std::string_view name, std::string_view uuid) const;

        struct MappedDevice
        {
            dev_t deviceNumber;
            std::string name;
        };

        LIBRALF_NS::Result<std::list<MappedDevice>> mappedDevices() const;

    private:
        static LIBRALF_NS::Result<> checkDeviceNameAndUuid(std::string_view name, std::string_view uuid);

        static std::string toHex(const uint8_t *bytes, size_t length);

        static std::string createTargetParams(unsigned loopDevMajor, unsigned loopDevMinor,
                                              const VeritySuperBlock &superBlock, const std::vector<uint8_t> &rootHash,
                                              uint64_t hashesOffset);

        static LIBRALF_NS::Result<VeritySuperBlock> readDmVeritySuperBlock(int devFd, uint64_t hashesOffset);

        dm_ioctl *initialiseCmdBuf(std::string_view name, std::string_view uuid) const;

        LIBRALF_NS::Result<> createDevice(uint64_t dataSize, std::string_view deviceName, std::string_view deviceUuid,
                                          std::string_view targetType, std::string_view targetParams,
                                          bool readOnly) const;

        LIBRALF_NS::Result<dev_t> activateDevice(std::string_view name, std::string_view uuid, bool readOnly,
                                                 bool useUDevSync) const;

        LIBRALF_NS::Result<> removeDevice(std::string_view name, std::string_view uuid, bool deferred) const;

        LIBRALF_NS::Result<std::string> deviceStatus(std::string_view name, std::string_view uuid) const;

        static LIBRALF_NS::Result<std::filesystem::path> findDeviceNode(dev_t dev);

    private:
        int m_controlFd = -1;
        LIBRALF_NS::VersionNumber m_version;

        mutable std::vector<uint8_t> m_cmdBuffer;
    };

} // namespace entos::ralf::dmverity