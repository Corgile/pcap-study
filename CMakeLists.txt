cmake_minimum_required(VERSION 3.25)
project(pcap_study)

set(target demo)
set(CMAKE_CXX_STANDARD 17)

set(PLATFORM "" CACHE STRING "Specify Target Platform")
# 使用变量来设置宏定义
add_compile_definitions(${PLATFORM})
message(STATUS "Current Platform: ${PLATFORM}")

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

add_executable(${target} main.cpp)

# target_link_libraries() 里面必须使用倒序，越基础的库越往后放 否则一堆undefined
target_link_libraries(${target} PRIVATE lib::process-api)
target_link_libraries(${target} PRIVATE lib::osi-headers)
target_link_libraries(${target} PRIVATE lib::common-util)
target_link_libraries(${target} PRIVATE lib::vendor-util)
