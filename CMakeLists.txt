cmake_minimum_required(VERSION 3.9)
project(libibverbscpp)

set(CMAKE_CXX_STANDARD 17)
#set(CMAKE_CXX_COMPILER clang++)
#set(WARNINGS "-Weverything -Wno-c++98-compat")
set(WARNINGS "-Wall -Wextra -Wnon-virtual-dtor -Wduplicated-cond -Wduplicated-branches -Wlogical-op -Wrestrict")
set(WARNINGS "${Warnings} -Wnull-dereference -Wold-style-cast -Wuseless-cast -Wjump-misses-init -Wdouble-promotion")
set(WARNINGS "${Warnings} -Wformat=2 -Wshadow=local -Wodr")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pedantic ${WARNINGS}")

add_library(libibverbscpp libibverbscpp.cpp libibverbscpp.h)