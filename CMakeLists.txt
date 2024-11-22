cmake_minimum_required(VERSION 3.28)

project(
    "Z Anti-Anti-Debugger"
    VERSION 0.0.1
    LANGUAGES C)

# Define source, include, and output directories
set(SRC_DIR "${CMAKE_SOURCE_DIR}/src")
set(INCLUDE_DIR "${CMAKE_SOURCE_DIR}/include")
set(BUILD_DIR "${CMAKE_SOURCE_DIR}/build")
set(TESTS_DIR "${CMAKE_SOURCE_DIR}/tests")
set(BIN_DIR "${CMAKE_SOURCE_DIR}/bin")

# Create output directories
file(MAKE_DIRECTORY ${BUILD_DIR} ${BIN_DIR})

# Set the compiler and flags
set(CMAKE_C_COMPILER gcc)
set(CMAKE_C_FLAGS "-Wall -Wextra -pedantic")
set(CMAKE_C_FLAGS_DEBUG "-g -O0")
set(CMAKE_C_FLAGS_RELEASE "-Oz")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Define an executable target "z" from source files
add_executable(z "${SRC_DIR}/z.c")
target_include_directories(z PRIVATE "${INCLUDE_DIR}")
set_target_properties(z PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})

# Define clang-tidy and clang-format commands as custom targets
find_program(LINTER clang-tidy)
find_program(FORMATTER clang-format)

add_custom_target(lint
    COMMAND ${LINTER} -p ${CMAKE_BINARY_DIR} --config-file=${CMAKE_SOURCE_DIR}/.clang-tidy ${SRC_DIR}/*.c ${INCLUDE_DIR}/*.h ${TESTS_DIR}/*.c
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_custom_target(format
    COMMAND find ${SRC_DIR} -name "*.c" -exec ${FORMATTER} -style=file -i {} +
    COMMAND find ${TESTS_DIR} -name "*.c" -exec ${FORMATTER} -style=file -i {} +
    COMMAND find ${INCLUDE_DIR} -name "*.h" -exec ${FORMATTER} -style=file -i {} +
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

# Tests using Criterion
find_package(PkgConfig REQUIRED)
pkg_check_modules(CRITERION REQUIRED criterion)

if(CRITERION_FOUND)
    include_directories(${CRITERION_INCLUDE_DIRS})
    link_directories(${CRITERION_LIBRARY_DIRS})
    add_definitions(${CRITERION_CFLAGS_OTHER})

    # Add test executable
    add_executable(z_tests "${TESTS_DIR}/test_z.c")
    target_include_directories(z_tests PRIVATE "${INCLUDE_DIR}")
    target_link_libraries(z_tests ${CRITERION_LIBRARIES})

    # Add test target
    add_custom_target(check
        COMMAND ${CMAKE_COMMAND} -E env CTEST_OUTPUT_ON_FAILURE=1 ${CMAKE_CTEST_COMMAND}
        DEPENDS z_tests
    )

    enable_testing()
    add_test(NAME ZProjectTests COMMAND z_tests)
else()
    message(FATAL_ERROR "Criterion library not found. Please install Criterion.")
endif()

# Define the "clean" target
add_custom_target(clean_all
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${BUILD_DIR}
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${BIN_DIR}
)
