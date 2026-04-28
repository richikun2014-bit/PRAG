cmake_minimum_required(VERSION 3.16)
project(PRAGPrototype LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(PRAG_FETCH_SEAL "Fetch Microsoft SEAL from the official repository when it is not installed" OFF)

if(PRAG_FETCH_SEAL)
    include(FetchContent)
    FetchContent_Declare(
        seal
        GIT_REPOSITORY https://github.com/microsoft/SEAL.git
        GIT_TAG v4.1.2
    )
    set(SEAL_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(SEAL_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(SEAL_BUILD_BENCH OFF CACHE BOOL "" FORCE)
    set(SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(seal)
else()
    find_package(SEAL 4.1 REQUIRED)
endif()

add_library(prag_core
    src/common/chebyshev.cpp
    src/common/mode_switch.cpp
    src/common/types.cpp
    src/client/crypto_utils.cpp
    src/client/interactive_client.cpp
    src/client/query_handler.cpp
    src/client/result_handler.cpp
    src/server/encrypted_index.cpp
    src/server/homomorphic_ops.cpp
    src/server/retrieval_prag1.cpp
    src/server/retrieval_prag2.cpp
    src/server/update_prag1.cpp
    src/server/update_prag2.cpp
)

target_include_directories(prag_core PUBLIC include)
if(TARGET SEAL::seal)
    target_link_libraries(prag_core PUBLIC SEAL::seal)
elseif(TARGET seal)
    target_link_libraries(prag_core PUBLIC seal)
else()
    message(FATAL_ERROR "Microsoft SEAL target was not found.")
endif()

add_executable(prag_demo apps/prag_demo.cpp)
target_link_libraries(prag_demo PRIVATE prag_core)

add_executable(prag_tests tests/prag_tests.cpp)
target_link_libraries(prag_tests PRIVATE prag_core)

enable_testing()
add_test(NAME prag_tests COMMAND prag_tests)
