cmake_minimum_required(VERSION 3.9)
project(libibverbscpp-example)

set(CMAKE_CXX_STANDARD 14)
set(WARNINGS "-Wall -Wextra -Wnon-virtual-dtor -Wduplicated-cond -Wduplicated-branches -Wlogical-op -Wrestrict")
set(WARNINGS "${WARNINGS} -Wnull-dereference -Wold-style-cast -Wuseless-cast -Wdouble-promotion")
set(WARNINGS "${WARNINGS} -Wformat=2 -Wshadow=local -Wodr")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pedantic ${WARNINGS}")

add_executable(example example.cpp)
target_include_directories(example SYSTEM PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(example ibverbs)
