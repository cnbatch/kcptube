cmake_minimum_required(VERSION 3.15.0 FATAL_ERROR)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(kcptube LANGUAGES C CXX)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

if(${CMAKE_SYSTEM_NAME} MATCHES "^DragonFly?" OR ${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD" OR ${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
	include_directories("/usr/local/include")
	include_directories("/usr/local/include/botan-2")
endif()
if(${CMAKE_SYSTEM_NAME} MATCHES "NetBSD")
	include_directories("/usr/pkg/include")
	include_directories("/usr/pkg/include/botan-2")
endif()
if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	include_directories("/usr/include/botan-2")
endif()

find_package(Threads REQUIRED)

find_package(OpenMP)
if (OPENMP_FOUND)
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
	set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
	set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN)
    add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
	add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")
endif()

add_executable(${PROJECT_NAME} src/main.cpp)

add_subdirectory(src)
set_property(TARGET kcptube PROPERTY
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

