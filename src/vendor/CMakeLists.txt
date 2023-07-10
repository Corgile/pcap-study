# Set the project name
project(vendor)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}              VENDOR_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/light-pcapng VENDOR_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/memplumber   VENDOR_SRC)

message(STATUS "======= 构建 lib::vendor-util =======")
foreach (file ${VENDOR_SRC})
    message(STATUS "添加源文件：${file} 到 ${PROJECT_NAME}")
endforeach ()

# Add a library with the above sources
add_library(${PROJECT_NAME} ${VENDOR_SRC})
add_library(lib::vendor-util ALIAS ${PROJECT_NAME})