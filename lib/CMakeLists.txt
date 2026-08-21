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


# This enables the dllexport/dllimport macros for the library, this is required for the library to be
# built as a shared library on Windows. The macro is defined in the LibRalf.h header.
add_compile_definitions(__LIBRALF_BUILD=1)

# Hide the symbols in the library by default
if (NOT DEFINED CMAKE_CXX_VISIBILITY_PRESET AND NOT DEFINED CMAKE_VISIBILITY_INLINES_HIDDEN)
    set(CMAKE_CXX_VISIBILITY_PRESET hidden)
    set(CMAKE_VISIBILITY_INLINES_HIDDEN YES)
endif ()


if (RALF_UTILS_ENABLE_EROFS)
    add_compile_definitions(ENABLE_EROFS=1)
    add_subdirectory(erofs)
endif ()

if (RALF_UTILS_ENABLE_W3C_WIDGET)
    set(RALF_UTILS_ENABLE_ARCHIVE ON)
    add_compile_definitions(ENABLE_W3C_WIDGET=1)
    add_subdirectory(w3c-widget)
    add_subdirectory(crypto/xmldsig)
endif ()

if (RALF_UTILS_ENABLE_OCI)
    set(RALF_UTILS_ENABLE_ARCHIVE ON)
    add_compile_definitions(ENABLE_OCI=1)
    add_subdirectory(oci)
    add_subdirectory(dm-verity)
    add_subdirectory(luks)
endif ()

if (RALF_UTILS_ENABLE_ARCHIVE)
    add_subdirectory(archive)
endif ()


add_subdirectory(core)
add_subdirectory(crypto/openssl)

configure_file(core/LibRalf.h.in ${CMAKE_CURRENT_BINARY_DIR}/LibRalf.h @ONLY)

set(libralf_COMPONENTS
        $<TARGET_OBJECTS:libralf-core>
        $<TARGET_OBJECTS:libralf-crypto-openssl>

        $<$<BOOL:${RALF_UTILS_ENABLE_ARCHIVE}>:$<TARGET_OBJECTS:libralf-archive>>

        $<$<BOOL:${RALF_UTILS_ENABLE_W3C_WIDGET}>:$<TARGET_OBJECTS:libralf-w3c-widget>>
        $<$<BOOL:${RALF_UTILS_ENABLE_W3C_WIDGET}>:$<TARGET_OBJECTS:libralf-crypto-xmldsig>>

        $<$<BOOL:${RALF_UTILS_ENABLE_OCI}>:$<TARGET_OBJECTS:libralf-oci>>
        $<$<BOOL:${RALF_UTILS_ENABLE_OCI}>:$<TARGET_OBJECTS:libralf-dm-verity>>
        $<$<BOOL:${RALF_UTILS_ENABLE_OCI}>:$<TARGET_OBJECTS:libralf-luks>>

        $<$<BOOL:${RALF_UTILS_ENABLE_EROFS}>:$<TARGET_OBJECTS:libralf-erofs>>
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(CRYPTSETUP REQUIRED IMPORTED_TARGET libcryptsetup)
pkg_check_modules(UUID REQUIRED IMPORTED_TARGET uuid)
pkg_check_modules(KEYUTILS REQUIRED IMPORTED_TARGET libkeyutils)

set(libralf_LIBDEPS
        LibXml2::LibXml2
        OpenSSL::Crypto

        $<$<BOOL:${RALF_UTILS_ENABLE_EROFS}>:lz4::lz4>
        $<$<BOOL:${RALF_UTILS_ENABLE_W3C_WIDGET}>:LibArchive::LibArchive>
        PkgConfig::CRYPTSETUP
        PkgConfig::UUID
        PkgConfig::KEYUTILS
)

if (BUILD_SHARED_LIBS)
    add_library(libralf SHARED ${libralf_COMPONENTS})
    target_compile_features(libralf PUBLIC cxx_std_17)
    target_link_libraries(libralf PRIVATE ${libralf_LIBDEPS})
endif ()

add_library(libralf-static STATIC ${libralf_COMPONENTS})
target_compile_features(libralf-static PUBLIC cxx_std_17)
target_link_libraries(libralf-static PRIVATE ${libralf_LIBDEPS})


# List of public headers for the library that get installed along with the library.
set(libralf_HEADERS

        ${CMAKE_CURRENT_BINARY_DIR}/LibRalf.h

        ../include/Certificate.h
        ../include/EnumFlags.h
        ../include/Error.h
        ../include/Logging.h
        ../include/Package.h
        ../include/PackageEntry.h
        ../include/PackageMetaData.h
        ../include/PackageAuxMetaData.h
        ../include/PackageReader.h
        ../include/PackageMount.h
        ../include/Result.h
        ../include/VerificationBundle.h
        ../include/VersionConstraint.h
        ../include/VersionNumber.h

        ../include/EntosTypes.h
)


# The library API version numbers, these versions are used for the API / ABI versioning and do not
# necessarily match the project version.
if (BUILD_SHARED_LIBS)
    set_target_properties(libralf
            PROPERTIES
            OUTPUT_NAME ralf
            VERSION ${RALF_UTILS_VERSION_MAJOR}.${RALF_UTILS_VERSION_MINOR}.${RALF_UTILS_VERSION_MICRO}
            SOVERSION ${RALF_UTILS_VERSION_MAJOR}
            PUBLIC_HEADER "${libralf_HEADERS}"
            INTERFACE_LINK_LIBRARIES ""
    )
endif ()

set_target_properties(libralf-static
        PROPERTIES
        OUTPUT_NAME ralf
        PUBLIC_HEADER "${libralf_HEADERS}"
        INTERFACE_LINK_LIBRARIES ""
)

# Make cache variables for install destinations
include(GNUInstallDirs)

# Get some standard install directories from CMake
set(INCLUDE_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR} CACHE PATH "Location of header files")
set(LIB_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR} CACHE PATH "Location of library files")

# Install the shared library
if (BUILD_SHARED_LIBS)
    install(TARGETS libralf
            EXPORT libralf-shared-target
            LIBRARY DESTINATION ${LIB_INSTALL_DIR}
            ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
            PUBLIC_HEADER DESTINATION ${INCLUDE_INSTALL_DIR}/ralf
    )

    install(EXPORT libralf-shared-target
            FILE libralfTarget.cmake
            NAMESPACE ralf-utils::
            DESTINATION ${LIB_INSTALL_DIR}/cmake/libralf
    )
endif ()

# Install the static library
install(TARGETS libralf-static
        EXPORT libralf-static-target
        LIBRARY DESTINATION ${LIB_INSTALL_DIR}
        ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
        PUBLIC_HEADER DESTINATION ${INCLUDE_INSTALL_DIR}/ralf
)

install(EXPORT libralf-static-target
        FILE libralfStaticTarget.cmake
        NAMESPACE ralf-utils::
        DESTINATION ${LIB_INSTALL_DIR}/cmake/libralf
)

# Generate and install the pkg-config file
configure_file(libralf.pc.in libralf.pc @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libralf.pc" DESTINATION ${LIB_INSTALL_DIR}/pkgconfig)

# Generate and install the CMake package configuration files
include(CMakePackageConfigHelpers)

configure_package_config_file(
        libralfConfig.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/libralfConfig.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libralf
        PATH_VARS
        INCLUDE_INSTALL_DIR
        LIB_INSTALL_DIR
)

write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/libralfConfigVersion.cmake
        VERSION ${CMAKE_PROJECT_VERSION}
        COMPATIBILITY AnyNewerVersion
)

install(
        FILES
        ${CMAKE_CURRENT_BINARY_DIR}/libralfConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/libralfConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libralf
)

