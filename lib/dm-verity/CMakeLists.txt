# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
# Copyright 2025 Comcast Cable Communications Management, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

add_library(libralf-dm-verity

        OBJECT
        DmVeritySuperBlock.cpp
        DmVerityVerifier.cpp
        DmVerityProtectedFile.cpp
)

if (UNIX AND NOT APPLE)
    target_sources(libralf-dm-verity
            PRIVATE
            DmVerityMounterLinux.cpp
            DmVerityMount.cpp
            DevMapper.cpp
            UDevNotifySemaphore.cpp
            DmVerityUtils.cpp
    )
endif ()


target_include_directories(libralf-dm-verity

        PRIVATE
        $<TARGET_PROPERTY:libralf-core,INCLUDE_DIRECTORIES>
)

target_compile_definitions(libralf-dm-verity

        PRIVATE
        LOG_TAG="dm-verity"
)

if (RALF_UTILS_CLANG_TIDY)
    set_target_properties(libralf-dm-verity
            PROPERTIES CXX_CLANG_TIDY "${RALF_UTILS_CLANG_TIDY_CMD}")
endif ()
