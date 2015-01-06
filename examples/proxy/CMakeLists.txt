find_package(Boost 1.54.0 REQUIRED
             COMPONENTS log system)
find_package(Threads REQUIRED)

set(proxy_SRCS main.cc)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -msse4 -DBOOST_LOG_DYN_LINK")
include_directories("${PROJECT_SOURCE_DIR}/include")
add_executable( proxy ${proxy_SRCS})
target_link_libraries( proxy elkvm ${Boost_LOG_LIBRARY} 
                        ${Boost_SYSTEM_LIBRARY}
                        ${CMAKE_THREAD_LIBS_INIT}
                     )
