cmake_minimum_required(VERSION 3.5)
project(ht)

set(CMAKE_CXX_COMPILER /usr/bin/clang++)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wconversion -Wshadow ${CMAKE_CXX_FLAGS}")
set(CMAKE_CXX_FLAGS "-fno-exceptions -fno-rtti -fno-omit-frame-pointer ${CMAKE_CXX_FLAGS}")
set(CMAKE_CXX_FLAGS "-fsanitize=leak -g ${CMAKE_CXX_FLAGS}")

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

EXECUTE_PROCESS(
        COMMAND git rev-parse HEAD
        OUTPUT_VARIABLE GIT_COMMIT
        OUTPUT_STRIP_TRAILING_WHITESPACE
)
add_definitions(-DBUILD_VERSION=\"${GIT_COMMIT}\")

include_directories(${CMAKE_CURRENT_LIST_DIR}/src)
aux_source_directory(${CMAKE_CURRENT_LIST_DIR}/src source_src)
add_executable(${PROJECT_NAME} ${source_src})
target_link_libraries(${PROJECT_NAME} crypto)
