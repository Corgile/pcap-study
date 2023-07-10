# Set the project name
project(headers)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/                 OSI_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/l2-datalink      OSI_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/l3-network       OSI_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/l4-transport     OSI_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/l5-session       OSI_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/l6-presentation  OSI_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/l7-application   OSI_SRC)

if (MSVC)
    # Disable VS warnings: Unknown pragma (4068), Zero-sized array in struct/union (4200), Possible loss of data (4244),
    # Possible loss of data (4267), Character may not be represented (4819)
    add_definitions("/wd4068 /wd4200 /wd4244 /wd4267 /wd4819 /utf-8")
endif ()

message(STATUS "======= 构建 lib::osi-headers =======")
foreach (file ${OSI_SRC})
    message(STATUS "添加源文件：${file} 到 ${PROJECT_NAME}")
endforeach ()

# Add a library with the above sources
add_library(${PROJECT_NAME} ${OSI_SRC})
add_library(lib::osi-headers ALIAS ${PROJECT_NAME})