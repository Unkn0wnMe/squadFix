cmake_minimum_required(VERSION 3.10)

project(SquadFix LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(POLICY CMP0026)
    cmake_policy(SET CMP0026 NEW)
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "squadFix requires a 64-bit build.")
endif()

set(WINDIVERT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/vendor/windivert)
set(WINDIVERT_INCLUDE_DIR ${WINDIVERT_DIR}/include)
set(WINDIVERT_LIB_DIR ${WINDIVERT_DIR}/x64)

include_directories(${WINDIVERT_INCLUDE_DIR})

add_executable(SquadFix src/main.cpp)

target_link_libraries(SquadFix
    PRIVATE
    ${WINDIVERT_LIB_DIR}/WinDivert.lib
    ws2_32
    wininet
    bcrypt
    advapi32
)

add_custom_command(TARGET SquadFix POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${WINDIVERT_LIB_DIR}/WinDivert.dll"
        "$<TARGET_FILE_DIR:SquadFix>"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${WINDIVERT_LIB_DIR}/WinDivert.sys"
        "$<TARGET_FILE_DIR:SquadFix>"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/serverlist.cfg"
        "$<TARGET_FILE_DIR:SquadFix>"
    COMMENT "Copying runtime dependencies..."
)