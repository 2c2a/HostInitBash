cmake_minimum_required(VERSION 3.15)
project(ZASCAHB VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
    json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(json)

add_executable(h_side_init
    src/main.cpp
    src/h_side_init.cpp
    admin_resource.rc
)

target_link_libraries(h_side_init PRIVATE
    nlohmann_json::nlohmann_json
    wininet
    bcrypt
    ws2_32
)

target_include_directories(h_side_init PRIVATE src)

set_property(TARGET h_side_init PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
