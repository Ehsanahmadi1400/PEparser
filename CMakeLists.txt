# Minimum required CMake version
cmake_minimum_required(VERSION 3.22.1)

# Project name
project(MyProject)

# Notice the C++ version
set(CMAKE_CXX_STANDARD 11)
# Add the executable
add_executable(my_executable main.cpp)
