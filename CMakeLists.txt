
cmake_minimum_required(VERSION 2.8)

project(BroPluginIKEv2)

include(BroPlugin)

bro_plugin_begin(Zeek IKEv2)
bro_plugin_cc(src/IKEv2.cc src/Plugin.cc)
bro_plugin_bif(src/events.bif src/types.bif)
bro_plugin_pac( src/IKEv2.pac
                src/IKEv2-protocol.pac
                src/IKEv2-analyzer.pac
            )
bro_plugin_dist_files(README CHANGES COPYING VERSION)
bro_plugin_end()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
