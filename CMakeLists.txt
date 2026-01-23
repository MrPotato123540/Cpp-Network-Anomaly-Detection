cmake_minimum_required(VERSION 3.10)
project(internship_project)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -Wall -Wextra")

set(OpenGL_GL_PREFERENCE GLVND)

find_package(PcapPlusPlus REQUIRED)
find_package(OpenGL REQUIRED)
find_package(glfw3 REQUIRED)

include_directories(include)
include_directories(imgui)
include_directories(imgui/backends)

file(GLOB SOURCES "src/*.cpp")

set(IMGUI_SOURCES
    imgui/imgui.cpp
    imgui/imgui_draw.cpp
    imgui/imgui_tables.cpp
    imgui/imgui_widgets.cpp
    imgui/backends/imgui_impl_glfw.cpp    
    imgui/backends/imgui_impl_opengl3.cpp 
)

add_executable(internship_project ${SOURCES} ${IMGUI_SOURCES})

target_link_libraries(internship_project
	PUBLIC
	PcapPlusPlus::Pcap++
	PcapPlusPlus::Packet++
	PcapPlusPlus::Common++
	pcap
	pthread
	glfw
	OpenGL::GL
)
