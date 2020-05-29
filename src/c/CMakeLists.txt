find_package(JNI 1.8 REQUIRED COMPONENTS Development)

add_library(cjarop SHARED rop.c load.c)
target_include_directories(cjarop PRIVATE ${JNI_INCLUDE_DIRS})

set_target_properties(cjarop PROPERTIES RUNTIME_OUTPUT_DIRECTORY_DEBUG "${PROJECT_SOURCE_DIR}/bin/Debug")
set_target_properties(cjarop PROPERTIES LIBRARY_OUTPUT_DIRECTORY_DEBUG "${PROJECT_SOURCE_DIR}/bin/Debug")
set_target_properties(cjarop PROPERTIES RUNTIME_OUTPUT_DIRECTORY_RELEASE "${PROJECT_SOURCE_DIR}/bin/Release")
set_target_properties(cjarop PROPERTIES LIBRARY_OUTPUT_DIRECTORY_RELEASE "${PROJECT_SOURCE_DIR}/bin/Release")
