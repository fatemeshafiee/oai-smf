cmake_minimum_required(VERSION 3.28)
project(nghttp2_starter)
set(CMAKE_CXX_STANDARD 17)

find_package(PkgConfig REQUIRED)

set(Boost_USE_STATIC_LIBS ON)
find_package(Boost 1.58.0 REQUIRED COMPONENTS system)

find_package(OpenSSL REQUIRED)
include(FetchContent)

FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz)
FetchContent_MakeAvailable(json)

file(GLOB SOURCES
        *.h
        *.cpp
)

add_executable(nghttp2_starter ${SOURCES})

# Just an example of how to put log in CMakeLists
# message(LOG="${Boost_LIBRARIES}")

target_include_directories(nghttp2_starter PRIVATE
        ${Boost_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        /usr/local/include/nghttp2
)

target_link_libraries(nghttp2_starter
        ${Boost_LIBRARIES}
        /usr/local/lib/libnghttp2_asio.a /usr/local/lib/libnghttp2.a
        ${OPENSSL_LIBRARIES}
        nlohmann_json::nlohmann_json
)
