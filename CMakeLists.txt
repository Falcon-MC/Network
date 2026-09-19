cmake_minimum_required(VERSION 3.16)
project(Falcon.Network LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

if (NOT TARGET FalconProtocol)
    FetchContent_Declare(
        falcon_protocol
        GIT_REPOSITORY https://github.com/Falcon-MC/Protocol.git
        GIT_TAG 0a0426fab3f074f34fc448e7727fa0a3aa21be27
        GIT_PROGRESS TRUE
    )
    FetchContent_MakeAvailable(falcon_protocol)
endif ()

if (NOT TARGET LibDataChannel::LibDataChannelStatic)
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
    set(BUILD_SHARED_DEPS_LIBS OFF CACHE BOOL "" FORCE)
    set(NO_MEDIA ON CACHE BOOL "" FORCE)
    set(NO_WEBSOCKET ON CACHE BOOL "" FORCE)
    set(NO_EXAMPLES ON CACHE BOOL "" FORCE)
    set(NO_TESTS ON CACHE BOOL "" FORCE)
    set(USE_GNUTLS OFF CACHE BOOL "" FORCE)
    set(USE_MBEDTLS OFF CACHE BOOL "" FORCE)
    set(USE_NICE OFF CACHE BOOL "" FORCE)

    FetchContent_Declare(
        libdatachannel
        GIT_REPOSITORY https://github.com/paullouisageneau/libdatachannel.git
        GIT_TAG 443f6934d9007eb7076ab7825ba330f355fcbead
        GIT_SHALLOW TRUE
        GIT_PROGRESS TRUE
    )
    FetchContent_MakeAvailable(libdatachannel)
endif ()

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
