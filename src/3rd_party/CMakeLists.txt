set(THISLIB_NAME THRID_PARTIES)

add_library(${THISLIB_NAME} STATIC "fecpp.cpp" "fecpp_ssse3.cpp" "ikcp.cpp")
string( TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" cmake_system_processor_lower )
if (cmake_system_processor_lower MATCHES "x86" OR cmake_system_processor_lower MATCHES "amd64" OR cmake_system_processor_lower MATCHES "i[36]86")
    set_source_files_properties(fecpp_ssse3.cpp PROPERTIES COMPILE_FLAGS "$<$<NOT:$<C_COMPILER_ID:MSVC>:-mssse3>")
    set_source_files_properties(fecpp_ssse3.cpp PROPERTIES COMPILE_FLAGS "$<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-mssse3>")
endif()

target_link_libraries(${THISLIB_NAME} PRIVATE SHAREDEFINES)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(${THISLIB_NAME} PUBLIC Threads::Threads)
