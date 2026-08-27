cmake_minimum_required(VERSION 3.16)
project(Falcon.Network LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB_RECURSE FALCON_NETWORK_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)

add_library(FalconNetwork STATIC ${FALCON_NETWORK_SOURCES})

target_include_directories(FalconNetwork PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

find_package(Threads REQUIRED)
find_package(ZLIB REQUIRED)
find_package(OpenSSL REQUIRED)

target_link_libraries(FalconNetwork PUBLIC Threads::Threads FalconProtocol LibDataChannel::LibDataChannelStatic)

if (WIN32)
    target_link_libraries(FalconNetwork PUBLIC ws2_32 z ssl crypto crypt32)
else ()
    target_link_libraries(FalconNetwork PUBLIC ZLIB::ZLIB OpenSSL::SSL OpenSSL::Crypto)
endif ()
