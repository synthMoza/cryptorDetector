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

set(ENCRYPT_SOURCE ${SOURCE_DIR}/encrypt.cpp ${SOURCE_DIR}/encryptor.cpp)
set(FANOTIFY_SOURCE ${SOURCE_DIR}/fanotify_wrapper.cpp ${SOURCE_DIR}/fanotify.cpp)

# encryptor executable
add_executable(encrypt ${ENCRYPT_SOURCE})
target_include_directories(encrypt PRIVATE ${INCLUDE_DIR})

# fanotify executable
add_executable(fanotify ${FANOTIFY_SOURCE})
target_include_directories(fanotify PRIVATE ${INCLUDE_DIR})
