# Set the project name
project(process)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} PROCESS_SRC)


if (MSVC)
    # Disable Visual Studio warnings: Unknown pragma (4068), Zero-sized array in struct/union (4200), Possible loss of data (4244),
    # Possible loss of data (4267), Character may not be represented (4819)
    # GCC "未知杂注"警告
    add_definitions("/wd4068 /wd4200 /wd4244 /wd4267 /wd4819 /utf-8")
endif ()

message(STATUS "======= 构建 lib::process-api =======")
foreach (file ${PROCESS_SRC})
    message(STATUS "添加源文件：${file} 到 ${PROJECT_NAME}")
endforeach ()


# Add a library with the above sources
add_library(${PROJECT_NAME} ${PROCESS_SRC})
add_library(lib::process-api ALIAS ${PROJECT_NAME})