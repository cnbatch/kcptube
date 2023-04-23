add_subdirectory(shares)
add_subdirectory(networks)

target_link_libraries(${PROJECT_NAME} PRIVATE NETCONNECTIONS)
target_link_libraries(${PROJECT_NAME} PRIVATE SHAREDEFINES)

if (WIN32)
	target_link_libraries(${PROJECT_NAME} PUBLIC wsock32 ws2_32)
endif()

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND NOT ${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
	target_link_libraries(${PROJECT_NAME} PUBLIC omp)
endif()

if (UNIX)
	target_link_libraries(${PROJECT_NAME} PUBLIC stdc++)
	target_link_libraries(${PROJECT_NAME} PUBLIC Threads::Threads)
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD" OR ${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
	target_link_libraries(${PROJECT_NAME} PRIVATE /usr/local/lib/libbotan-2.a)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "NetBSD")
	target_link_libraries(${PROJECT_NAME} PRIVATE /usr/pkg/lib/libbotan-2.a)
else()
	#list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../cmake")
	#find_package(Botan REQUIRED)
	#target_link_libraries(${PROJECT_NAME} PRIVATE Botan::Botan)
	target_link_libraries(${PROJECT_NAME} PRIVATE botan-2)
endif()

#if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
#	target_link_libraries(${PROJECT_NAME} PUBLIC uring)
#endif()

add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")
set_property(TARGET ${PROJECT_NAME} PROPERTY
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
