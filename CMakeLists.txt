cmake_minimum_required(VERSION 3.9)
project(libibverbscpp)

set(CMAKE_CXX_STANDARD 14)
#set(CMAKE_CXX_COMPILER clang++)
#set(WARNINGS "-Weverything -Wno-c++98-compat -Wno-documentation-unknown-command")
set(WARNINGS "-Wall -Wextra -Wnon-virtual-dtor -Wduplicated-cond -Wduplicated-branches -Wlogical-op -Wrestrict")
set(WARNINGS "${WARNINGS} -Wnull-dereference -Wold-style-cast -Wuseless-cast -Wdouble-promotion")
set(WARNINGS "${WARNINGS} -Wformat=2 -Wshadow=local -Wodr")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pedantic ${WARNINGS}")

add_library(libibverbscpp libibverbscpp.cpp libibverbscpp.h)