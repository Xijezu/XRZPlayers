cmake_minimum_required(VERSION 3.7)
project(XRZPlayers)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/modules")
set(CMAKE_CXX_STANDARD 11)

add_subdirectory(boost)

set(SOURCE_FILES main.cpp XRc4Cipher.cpp Packets.hpp)
add_executable(XRZPlayers ${SOURCE_FILES})

target_link_libraries(XRZPlayers boost -pthread)
