cmake_minimum_required(VERSION 3.16)
project(OmniUtils LANGUAGES CXX)

# --- 0. Detección de la Raíz de Proyectos (Sin usar "../") ---
get_filename_component(PROYECTOS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}" DIRECTORY)

# --- Configuración inteligente para compilación manual ---
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        set(CMAKE_INSTALL_PREFIX "/usr/local" CACHE PATH "Directorio de instalación" FORCE)
    else()
        set(CMAKE_INSTALL_PREFIX "${PROYECTOS_ROOT}/.omni-dev-sdk" CACHE PATH "Directorio de instalación" FORCE)
    endif()
endif()

# Forzar la subcarpeta para aislar los headers (ej. include/OmniUtils)
include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

set(INCLUDE_DIR "${CMAKE_BINARY_DIR}/OmniUtils/Include")
set(LIBS_DIR "${CMAKE_BINARY_DIR}/OmniUtils")

if(WIN32)
    set(ARCHIVE_DIR "${CMAKE_BINARY_DIR}/OmniUtils/Libs")
else()
    set(ARCHIVE_DIR "${LIBS_DIR}")
endif()

add_library(OmniUtils SHARED
    Base64.cpp
    Hasher.cpp
    JWT.cpp
    ConfigDB.cpp
    Logger.cpp
    DeviceRegistry.cpp
    Http/HttpServer.cpp
    Http/Router.cpp
    Logger.hpp
)

add_library(OmniUtils::OmniUtils ALIAS OmniUtils)

target_include_directories(OmniUtils PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

if(ANDROID)
    target_link_libraries(OmniUtils PUBLIC
        sodium
        Boost::json
    )
else()
    find_library(SODIUM_LIB sodium REQUIRED)
    find_package(Boost REQUIRED COMPONENTS json filesystem log log_setup date_time thread)

    target_link_libraries(OmniUtils PUBLIC
        ${SODIUM_LIB}
        Boost::json
        Boost::filesystem
        Boost::log
        Boost::log_setup
        Boost::date_time
        Boost::thread
    )
endif()

if(WIN32)
    set_target_properties(OmniUtils PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${LIBS_DIR}"
        LIBRARY_OUTPUT_DIRECTORY "${LIBS_DIR}"
        ARCHIVE_OUTPUT_DIRECTORY "${ARCHIVE_DIR}"
    )
else()
    set_target_properties(OmniUtils PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY "${LIBS_DIR}"
        RUNTIME_OUTPUT_DIRECTORY "${LIBS_DIR}"
        ARCHIVE_OUTPUT_DIRECTORY "${ARCHIVE_DIR}"
    )
endif()

if(WIN32)
    # Eliminamos el uso de "../bin" extrayendo el directorio padre directamente
    get_filename_component(SODIUM_LIB_DIR "${SODIUM_LIB}" DIRECTORY)
    get_filename_component(SODIUM_PARENT_DIR "${SODIUM_LIB_DIR}" DIRECTORY)

    find_file(SODIUM_DLL 
        NAMES "libsodium.dll" "sodium.dll" "libsodium-26.dll"
        HINTS "${SODIUM_PARENT_DIR}/bin" "${SODIUM_LIB_DIR}"
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
        get_filename_component(BOOST_PARENT_DIR "${FIRST_LIB_DIR}" DIRECTORY)
        set(BOOST_BIN_DIR "${BOOST_PARENT_DIR}/bin")
    elseif(DEFINED Boost_LIBRARIES)
        list(GET Boost_LIBRARIES 0 FIRST_LIB)
        if(EXISTS "${FIRST_LIB}")
            get_filename_component(FIRST_LIB_DIR "${FIRST_LIB}" DIRECTORY)
            get_filename_component(BOOST_PARENT_DIR "${FIRST_LIB_DIR}" DIRECTORY)
            set(BOOST_BIN_DIR "${BOOST_PARENT_DIR}/bin")
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

endif()

file(GLOB_RECURSE PUBLIC_HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/*.hpp"
)

foreach(HDR ${PUBLIC_HEADERS})
    file(RELATIVE_PATH REL_PATH "${CMAKE_CURRENT_SOURCE_DIR}" "${HDR}")
    set(DEST_PATH "${INCLUDE_DIR}/${REL_PATH}")

    get_filename_component(DEST_DIR "${DEST_PATH}" DIRECTORY)
    add_custom_command(TARGET OmniUtils POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${DEST_DIR}"
        COMMAND ${CMAKE_COMMAND} -E copy "${HDR}" "${DEST_PATH}"
    )
endforeach()

# --- Installation & Export ---
install(TARGETS OmniUtils
    EXPORT OmniUtilsTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}
    FILES_MATCHING PATTERN "*.hpp" PATTERN "*.h"
    PATTERN "build" EXCLUDE
    PATTERN ".git" EXCLUDE
    PATTERN ".vscode" EXCLUDE
)

file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/OmniUtilsConfig.cmake"
"include(CMakeFindDependencyMacro)\n"
"find_dependency(Boost REQUIRED COMPONENTS json filesystem log log_setup date_time thread)\n"
"include(\"\${CMAKE_CURRENT_LIST_DIR}/OmniUtilsTargets.cmake\")\n"
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/OmniUtilsConfig.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/OmniUtils
)

install(EXPORT OmniUtilsTargets
    FILE OmniUtilsTargets.cmake
    NAMESPACE OmniUtils::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/OmniUtils
)