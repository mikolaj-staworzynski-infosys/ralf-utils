add_library(libralf-luks  OBJECT)

if (UNIX AND NOT APPLE)
    target_sources(libralf-luks
            PRIVATE
            LuksVerityMount.cpp
            LuksMounterLinux.cpp
    )
endif ()

target_link_libraries(libralf-luks PRIVATE libralf-core)

target_compile_definitions(libralf-luks PRIVATE LOG_TAG="luks")

if (RALF_UTILS_CLANG_TIDY)
    set_target_properties(libralf-luks PROPERTIES CXX_CLANG_TIDY "${RALF_UTILS_CLANG_TIDY_CMD}")
endif ()
