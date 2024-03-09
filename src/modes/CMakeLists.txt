set(THISLIB_NAME RUNNINGMODES)

add_library(${THISLIB_NAME} STATIC client.cpp server.cpp relay.cpp tester.cpp)
target_link_libraries(${THISLIB_NAME} PRIVATE SHAREDEFINES)
target_link_libraries(${PROJECT_NAME} PRIVATE NETCONNECTIONS)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(${THISLIB_NAME} PUBLIC Threads::Threads)
