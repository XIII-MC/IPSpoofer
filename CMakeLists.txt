cmake_minimum_required(VERSION 3.30)
project(IPSpoofer)

set(CMAKE_CXX_STANDARD 26)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(NPCAP_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/libs/npcap/include)
set(NPCAP_LIB_DIR ${CMAKE_SOURCE_DIR}/libs/npcap/)

include_directories(${NPCAP_INCLUDE_DIR})
link_directories(${NPCAP_LIB_DIR})

add_executable(IPSpoofer main.cpp)

target_link_libraries(IPSpoofer wpcap packet)
target_link_libraries(IPSpoofer ws2_32)