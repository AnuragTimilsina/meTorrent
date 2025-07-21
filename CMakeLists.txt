cmake_minimum_required(VERSION 3.13)

project(codecrafters-bittorrent)

set(CMAKE_CXX_STANDARD 23) # Enable C++23 standard

file(GLOB_RECURSE SOURCE_FILES src/*.cpp src/*.hpp)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED) # Added curl library

add_executable(bittorrent ${SOURCE_FILES})

target_link_libraries(bittorrent PRIVATE OpenSSL::Crypto CURL::libcurl) # Add CURL linking here
