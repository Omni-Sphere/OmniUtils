cmake_minimum_required(VERSION 3.16)
project(OmniUtils LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(WIN32)
    set(DEST_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/Win64)
elseif(APPLE)
    set(DEST_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/macOS)
else()
    set(DEST_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/Linux)
endif()

add_library(OmniUtils SHARED
    Base64.cpp
    Hasher.cpp
    JWT.cpp
)

target_include_directories(OmniUtils
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
)

find_library(SODIUM_LIB sodium REQUIRED)
find_package(Boost REQUIRED COMPONENTS json)

target_link_libraries(OmniUtils PUBLIC
    ${SODIUM_LIB}
    Boost::json
)

set_target_properties(OmniUtils PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${DEST_LIB_DIR}
    LIBRARY_OUTPUT_DIRECTORY ${DEST_LIB_DIR}
    ARCHIVE_OUTPUT_DIRECTORY ${DEST_LIB_DIR}
)

file(GLOB_RECURSE PUBLIC_HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/*.hpp"
)

foreach(HDR ${PUBLIC_HEADERS})
    file(RELATIVE_PATH REL_PATH "${CMAKE_CURRENT_SOURCE_DIR}" "${HDR}")
    set(DEST_PATH "${DEST_LIB_DIR}/OmniUtils/${REL_PATH}")

    get_filename_component(DEST_DIR "${DEST_PATH}" DIRECTORY)
    add_custom_command(TARGET OmniUtils POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${DEST_DIR}"
        COMMAND ${CMAKE_COMMAND} -E copy "${HDR}" "${DEST_PATH}"
    )
endforeach()
