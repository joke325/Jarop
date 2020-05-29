cmake_minimum_required(VERSION 3.10)

project(Jarop VERSION 0.2)
set(CMAKE_BUILD_TYPE Release)

file(REMOVE_RECURSE "${PROJECT_SOURCE_DIR}/bin")
file(MAKE_DIRECTORY "${PROJECT_SOURCE_DIR}/bin" "${PROJECT_SOURCE_DIR}/bin/Debug" "${PROJECT_SOURCE_DIR}/bin/Release")

add_subdirectory(src/c)
add_subdirectory(src/java)
