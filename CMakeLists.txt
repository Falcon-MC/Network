cmake_minimum_required(VERSION 3.16)
project(Falcon.Network LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(FalconNetwork STATIC
        src/RakNet/BitStream.cpp
        src/RakNet/GetTime.cpp
        src/RakNet/RakNetTypes.cpp
        src/RakNet/RakNetSocket2.cpp
        src/RakNet/ReliabilityLayer.cpp
        src/RakNet/RakPeer.cpp
)

target_include_directories(FalconNetwork PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

find_package(Threads REQUIRED)
target_link_libraries(FalconNetwork PUBLIC Threads::Threads)

if (WIN32)
    target_link_libraries(FalconNetwork PUBLIC ws2_32)
endif ()
