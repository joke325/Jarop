find_package(Java 1.8 REQUIRED COMPONENTS Development)
include(UseJava)

set(JAROP_JAR_NAME    jarop)
set(JAROP_JAR_VERSION 0.2)

set(JAROP_JAR_OUTDIR "${PROJECT_SOURCE_DIR}/bin/Release")
set(JAROP_JAR_PATH "${JAROP_JAR_OUTDIR}/${JAROP_JAR_NAME}-${JAROP_JAR_VERSION}.jar")

file(GLOB SRC_FILES LIST_DIRECTORIES false RELATIVE "${CMAKE_CURRENT_LIST_DIR}" tech/janky/jarop/*.java tech/janky/jarop/rop/*.java)

add_jar(jarop ${SRC_FILES} VERSION ${JAROP_JAR_VERSION} OUTPUT_NAME ${JAROP_JAR_NAME} OUTPUT_DIR "${JAROP_JAR_OUTDIR}")

add_custom_command(TARGET jarop POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy "${JAROP_JAR_PATH}" "${PROJECT_SOURCE_DIR}/bin/Debug/")
