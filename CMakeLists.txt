cmake_minimum_required(VERSION 3.16)
project(OmniUtils LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(LIBS_DIR "${CMAKE_BINARY_DIR}/Libs")
set(INCLUDE_DIR "${CMAKE_BINARY_DIR}/Include")

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
    RUNTIME_OUTPUT_DIRECTORY "${LIBS_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${LIBS_DIR}"
    ARCHIVE_OUTPUT_DIRECTORY "${LIBS_DIR}"
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
            COMMAND ${CMAKE_COMMAND} -E copy_if_different "${SODIUM_DLL}" "${LIBS_DIR}"
            COMMENT "Copying Sodium DLL..."
        )
    else()
        message(WARNING "Could NOT find Sodium DLL. You may need to copy it manually to ${LIBS_DIR}")
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
                COMMAND ${CMAKE_COMMAND} -E copy_if_different "${DLL}" "${LIBS_DIR}"
                COMMENT "Copying Boost DLL: ${DLL}"
            )
        endforeach()
    endif()

elseif(UNIX)
    # Sodium
    if(EXISTS "${SODIUM_LIB}")
        add_custom_command(TARGET OmniUtils POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different "${SODIUM_LIB}" "${LIBS_DIR}"
            COMMENT "Copying Sodium Library: ${SODIUM_LIB}"
        )
    endif()

    # Boost
    # Try to get the location from the imported target if possible, or fall back to known variables.
    if(TARGET Boost::json)
        get_target_property(BOOST_JSON_LIB Boost::json IMPORTED_LOCATION)
        if(NOT BOOST_JSON_LIB)
            get_target_property(BOOST_JSON_LIB Boost::json IMPORTED_LOCATION_RELEASE)
        endif()

        if(BOOST_JSON_LIB AND EXISTS "${BOOST_JSON_LIB}")
            add_custom_command(TARGET OmniUtils POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different "${BOOST_JSON_LIB}" "${LIBS_DIR}"
                COMMENT "Copying Boost Json Library: ${BOOST_JSON_LIB}"
            )
        endif()
    endif()
    
    # Try to find container lib if linked implicitly or via other components
    # Just generic handling if Boost_LIBRARIES is available
    foreach(LIB ${Boost_LIBRARIES})
        if(EXISTS "${LIB}" AND NOT IS_DIRECTORY "${LIB}")
             add_custom_command(TARGET OmniUtils POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different "${LIB}" "${LIBS_DIR}"
                COMMENT "Copying Boost Library: ${LIB}"
            )
        endif()
    endforeach()
endif()

file(GLOB_RECURSE PUBLIC_HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/*.hpp"
)

foreach(HDR ${PUBLIC_HEADERS})
    file(RELATIVE_PATH REL_PATH "${CMAKE_CURRENT_SOURCE_DIR}" "${HDR}")
    set(DEST_PATH "${INCLUDE_DIR}/${REL_PATH}") # Removed /OmniUtils/ prefix based on user request "Include where headers go" - usually better flat or mirroring source depending on need. I'll stick to mirroring source relative path directly into Include for now, or if they want an 'OmniUtils' subdir, I can add it. The original code had /OmniUtils/. The user request says "otra como include donde vayan las cabezzeras". I will assume simpler structure or maybe just keeping the relative path is safest. Let's start with clean mirror. Wait, previous code had /OmniUtils/. Standard practice is Include/OmniUtils/file.hpp so user does #include <OmniUtils/file.hpp>. Let's keep the /OmniUtils/ subfolder structure if it makes sense, but the user just said "Include". I'll default to just putting them in Include, preserving internal folder structure if any.
    # Actually, looking at the previous code: set(DEST_PATH "${DEST_LIB_DIR}/OmniUtils/${REL_PATH}")
    # The user request: "Include donde vayan las cabezzeras"
    # I will put them in Include/OmniUtils to keep namespace clean, it's safer.
    
    set(DEST_PATH "${INCLUDE_DIR}/OmniUtils/${REL_PATH}")

    get_filename_component(DEST_DIR "${DEST_PATH}" DIRECTORY)
    add_custom_command(TARGET OmniUtils POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${DEST_DIR}"
        COMMAND ${CMAKE_COMMAND} -E copy "${HDR}" "${DEST_PATH}"
    )
endforeach()
