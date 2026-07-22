#pragma once

#include <string>
#include "DevMapper.h"
#include "IDmVerityMounter.h"
#include <unistd.h>

namespace entos::ralf::dmverity {

class DmVerityUtils {
public:
    static Result<std::pair<std::string, std::string>> createDeviceNameAndUuid(
        const DevMapper &devMapper,
        std::string_view id, 
        const uint8_t uuid[16]);

    static std::string bytesToHexString(const uint8_t *bytes, size_t length);
    static std::filesystem::path procPathToFd(int fd);
    static size_t calcRequiredHashBlocks(size_t dataBlocks, size_t blockSize);
    static Result<VeritySuperBlock> readDmVeritySuperBlock(int imageFileFd, IDmVerityMounter::FileRange dataRange,
                                                           IDmVerityMounter::FileRange hashesRange);
    static Result<std::filesystem::path> getFreeLoopDevice();
    static Result<int> loopDeviceAttach(int imageFd, IDmVerityMounter::FileRange fileRange, MountFlags flags);
    static Result<> checkFileRanges(int imageFd, IDmVerityMounter::FileRange dataRange,
                                    IDmVerityMounter::FileRange hashesRange);
};

}