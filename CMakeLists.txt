cmake_minimum_required(VERSION 3.10)
project(cryptum CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_INSTALL_RPATH "$ORIGIN")

if(MSVC)
	add_compile_options(/W4 /WX /utf-8)
else()
	add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

add_library(common STATIC common/random_bytes.cpp common/secure_memory.cpp)
target_include_directories(common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/common ${CMAKE_CURRENT_SOURCE_DIR}/include)
set_target_properties(common PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_executable(cryptum src/main.cpp src/cli_options.cpp src/byte_io.cpp src/platform.cpp)
target_link_libraries(cryptum PRIVATE common)
