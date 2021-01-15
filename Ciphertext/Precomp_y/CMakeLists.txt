# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.10)

project(SEALExamples VERSION 3.1.0 LANGUAGES CXX)

# Executable will be in ../bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY)

add_executable(precomp_y precomp_y.cpp)

# Import SEAL
find_package(SEAL 3.1.0 EXACT REQUIRED)

# Link SEAL
target_link_libraries(precomp_y SEAL::seal)
