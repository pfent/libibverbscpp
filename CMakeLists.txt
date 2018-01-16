cmake_minimum_required(VERSION 3.9)
project(libibverbscpp)

#set(CMAKE_CXX_COMPILER clang++)
#set(WARNINGS "-Weverything -Wno-c++98-compat")
set(CMAKE_CXX_STANDARD 17)
set(WARNINGS "-Wall -Wextra -Wnon-virtual-dtor -Wold-style-cast")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pedantic ${WARNINGS}")

add_library(libibverbscpp libibverbscpp.cpp libibverbscpp.h)