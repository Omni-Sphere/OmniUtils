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
    Logger.hpp
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

if(WIN32)
    get_filename_component(SODIUM_LIB_DIR "${SODIUM_LIB}" DIRECTORY)

    find_file(SODIUM_DLL 
        NAMES "libsodium.dll" "sodium.dll" "libsodium-26.dll"
        HINTS "${SODIUM_LIB_DIR}/../bin" "${SODIUM_LIB_DIR}"
    )
    
    if(SODIUM_DLL)
        message(STATUS "Found Sodium DLL: ${SODIUM_DLL}")
        add_custom_command(TARGET OmniUtils POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different "${SODIUM_DLL}" "${DEST_LIB_DIR}"
            COMMENT "Copying Sodium DLL..."
        )
    else()
        message(WARNING "Could NOT find Sodium DLL. You may need to copy it manually to ${DEST_LIB_DIR}")
    endif()

    set(BOOST_BIN_DIR "")
    if(DEFINED Boost_LIBRARY_DIRS)
        list(GET Boost_LIBRARY_DIRS 0 FIRST_LIB_DIR)
        set(BOOST_BIN_DIR "${FIRST_LIB_DIR}/../bin")
    elseif(DEFINED Boost_LIBRARIES)
        list(GET Boost_LIBRARIES 0 FIRST_LIB)
        if(EXISTS "${FIRST_LIB}")
            get_filename_component(FIRST_LIB_DIR "${FIRST_LIB}" DIRECTORY)
            set(BOOST_BIN_DIR "${FIRST_LIB_DIR}/../bin")
        endif()
    endif()

    if(BOOST_BIN_DIR AND EXISTS "${BOOST_BIN_DIR}")
        file(GLOB BOOST_DLLS "${BOOST_BIN_DIR}/*boost_json*.dll" "${BOOST_BIN_DIR}/*boost_container*.dll")
        foreach(DLL ${BOOST_DLLS})
            add_custom_command(TARGET OmniUtils POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different "${DLL}" "${DEST_LIB_DIR}"
                COMMENT "Copying Boost DLL: ${DLL}"
            )
        endforeach()
    endif()
endif()

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
