cmake_minimum_required(VERSION 3.14)
project(netanomaly)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -Wall -Wextra")
set(OpenGL_GL_PREFERENCE GLVND)

find_package(PcapPlusPlus REQUIRED)
find_package(OpenGL REQUIRED)
find_package(glfw3 REQUIRED)

# Dear ImGui is fetched at configure time instead of being vendored,
# so a plain `git clone` of this repo is enough to build.
include(FetchContent)
FetchContent_Declare(imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG        v1.90.4
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(imgui)

set(IMGUI_SOURCES
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp
)

file(GLOB SOURCES "src/*.cpp")

add_executable(netanomaly ${SOURCES} ${IMGUI_SOURCES})

target_include_directories(netanomaly
    PRIVATE
        include
        ${imgui_SOURCE_DIR}
        ${imgui_SOURCE_DIR}/backends
)

target_link_libraries(netanomaly
    PUBLIC
        PcapPlusPlus::Pcap++
        PcapPlusPlus::Packet++
        PcapPlusPlus::Common++
        pcap
        pthread
        glfw
        OpenGL::GL
)
