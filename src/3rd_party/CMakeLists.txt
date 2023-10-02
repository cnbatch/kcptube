set(THISLIB_NAME THRID_PARTIES)

add_library(${THISLIB_NAME} STATIC "ikcp.cpp")
target_link_libraries(${THISLIB_NAME} PRIVATE SHAREDEFINES)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(${THISLIB_NAME} PUBLIC Threads::Threads)

