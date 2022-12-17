cmake_minimum_required(VERSION 3.1)
project(fanotify)

# Set up flags, standard and debug/release configurations
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

message(STATUS "CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}")

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -Werror")
set(CMAKE_CXX_FLAGS_DEBUG "-g -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

set(SOURCE_DIR src)
set(INCLUDE_DIR include)

set(ENCRYPT_SOURCE 
    ${SOURCE_DIR}/cryptor/encrypt.cpp
    ${SOURCE_DIR}/cryptor/encryptor.cpp
)
set(FANOTIFY_SOURCE
    ${SOURCE_DIR}/fanotify/config.cpp
    ${SOURCE_DIR}/fanotify/detector.cpp
    ${SOURCE_DIR}/fanotify/fanotify_helpers.cpp
    ${SOURCE_DIR}/fanotify/fanotify_wrapper.cpp
    ${SOURCE_DIR}/fanotify/fanotify.cpp
    
    ${SOURCE_DIR}/sqlite/sqlite3.c
    ${SOURCE_DIR}/sqlite/filedb.cpp
)

set(FANOTIFY_DAEMON_SOURCE
    ${SOURCE_DIR}/fanotify/config.cpp
    ${SOURCE_DIR}/fanotify/detector.cpp
    ${SOURCE_DIR}/fanotify/fanotify_helpers.cpp
    ${SOURCE_DIR}/fanotify/fanotify_wrapper.cpp
    ${SOURCE_DIR}/fanotify/fanotify_daemon.cpp
    
    ${SOURCE_DIR}/sqlite/sqlite3.c
    ${SOURCE_DIR}/sqlite/filedb.cpp
)

# JSON lib for config
set(JSON_BuildTests OFF CACHE INTERNAL "") # disable tests
add_subdirectory(3rd_party/json-3.11.2)

# encryptor executable
add_executable(encrypt ${ENCRYPT_SOURCE})
target_include_directories(encrypt PRIVATE ${INCLUDE_DIR})

find_package(Threads REQUIRED)

# fanotify executable
add_executable(fanotify ${FANOTIFY_SOURCE})
target_include_directories(fanotify PRIVATE ${INCLUDE_DIR})
target_link_libraries(fanotify PRIVATE nlohmann_json::nlohmann_json)

# fanotify daemon
add_executable(fanotify_daemon ${FANOTIFY_DAEMON_SOURCE})
target_include_directories(fanotify_daemon PRIVATE ${INCLUDE_DIR})
target_link_libraries(fanotify_daemon PRIVATE nlohmann_json::nlohmann_json)
target_compile_definitions(fanotify_daemon PUBLIC DAEMON_FANOTIFY)
