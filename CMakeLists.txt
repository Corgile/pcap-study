cmake_minimum_required(VERSION 3.25)
project(pcap_study)

set(target demo)
set(CMAKE_CXX_STANDARD 17)

if (WIN32)
    message(STATUS "================= INCLUDE: windows环境==================")
    set(PCAP_ROOT D:/environment/npcap-sdk/v1.13)
    include_directories(${PCAP_ROOT}/Include)
endif ()

include_directories(
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/include/common
        ${PROJECT_SOURCE_DIR}/include/vendor
        ${PROJECT_SOURCE_DIR}/include/process
        ${PROJECT_SOURCE_DIR}/include/osi
        ${PROJECT_SOURCE_DIR}/include/osi/l2-datalink
        ${PROJECT_SOURCE_DIR}/include/osi/l3-network
        ${PROJECT_SOURCE_DIR}/include/osi/l4-transport
        ${PROJECT_SOURCE_DIR}/include/osi/l5-session
        ${PROJECT_SOURCE_DIR}/include/osi/l6-presentation
        ${PROJECT_SOURCE_DIR}/include/osi/l7-application
        ${PROJECT_SOURCE_DIR}/include/vendor/memplumber
        ${PROJECT_SOURCE_DIR}/include/vendor/light-pcapng)

add_subdirectory(src/common)
add_subdirectory(src/headers)
add_subdirectory(src/process)
add_subdirectory(src/vendor)


if (MSVC)
    # Disable VS warnings: Unknown pragma (4068), Zero-sized array in struct/union (4200), Possible loss of data (4244),
    # Possible loss of data (4267), Character may not be represented (4819)
    add_definitions("/wd4068 /wd4200 /wd4244 /wd4267 /wd4819 /utf-8")
endif ()

add_executable(${target} main.cpp api.cpp ${ALL_SOURCES})

if (WIN32)
    message(STATUS "=================== LINK: windows环境 ==================")
    target_link_libraries(${target} PRIVATE
            ${PCAP_ROOT}/Lib/x64/wpcap.lib
            ${PCAP_ROOT}/Lib/x64/Packet.lib)
    target_link_libraries(${target} PRIVATE ws2_32 iphlpapi)
elseif (UNIX)
    target_link_libraries(${target} PRIVATE pcap)
endif ()

target_link_libraries(${target} PRIVATE lib::common-util)
target_link_libraries(${target} PRIVATE lib::process-api)
target_link_libraries(${target} PRIVATE lib::osi-headers)