cmake_minimum_required(VERSION 3.10)
project(ws28 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON) # exports a compilation DB for clang-tidy

if (APPLE)
  # settings for Homebrew
  include_directories(/opt/homebrew/include)
endif (APPLE)

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBUV REQUIRED IMPORTED_TARGET libuv)

add_library(ws28 OBJECT
  src/Client.cpp
  src/Client.h
  src/Headers.h
  src/Server.cpp
  src/Server.h
  src/TLS.h
  )

add_executable(echo echo.cpp)
target_include_directories(echo PRIVATE ${LIBUV_INCLUDE_DIRS})
target_link_libraries(echo
  ws28
  PkgConfig::LIBUV
  OpenSSL::SSL
  #OpenSSL::Crypto
  )

add_custom_target(__prebuild__ ALL
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${PROJECT_BINARY_DIR}/compile_commands.json"
    "${PROJECT_SOURCE_DIR}"
  )
