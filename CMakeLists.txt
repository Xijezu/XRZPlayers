cmake_minimum_required(VERSION 3.7)
project(XRZPlayers)

set(CMAKE_CXX_STANDARD 11)

find_package(Boost REQUIRED COMPONENTS system)

set(SOURCE_FILES main.cpp XRc4Cipher.cpp Packets.hpp)
add_executable(XRZPlayers ${SOURCE_FILES})

target_link_libraries(XRZPlayers ${Boost_LIBRARIES})