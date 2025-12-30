cmake_minimum_required(VERSION 3.16)
project(ReplicaPulse LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Enable LTO for Release builds by default
if(NOT DEFINED CMAKE_INTERPROCEDURAL_OPTIMIZATION)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO ON)
endif()

# Optimize for the build machine architecture in Release mode
if(CMAKE_BUILD_TYPE MATCHES "Release" OR CMAKE_BUILD_TYPE MATCHES "RelWithDebInfo")
    if(NOT DEFINED DISABLE_NATIVE_ARCH)
        add_compile_options(-march=native)
    endif()
endif()

option(ENABLE_SANITIZERS "Enable address/UB sanitizers for leak detection" OFF)
if (ENABLE_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

find_package(OpenSSL REQUIRED)

add_library(replicapulse
    src/connection.cpp
    src/event_parser.cpp
    src/checkpoint.cpp
    src/gtid_set.cpp
    src/gtid_tracker.cpp
    src/ha.cpp
    src/sql_formatter.cpp
    src/service.cpp
    src/table_metadata.cpp
    src/threading.cpp
    src/output.cpp)

target_include_directories(replicapulse PUBLIC include)

target_link_libraries(replicapulse PUBLIC OpenSSL::SSL OpenSSL::Crypto pthread)

add_executable(replicapulse_cli src/main.cpp)
target_link_libraries(replicapulse_cli PRIVATE replicapulse)
set_target_properties(replicapulse_cli PROPERTIES OUTPUT_NAME "replicapulse")

enable_testing()
add_executable(sql_formatter_test tests/sql_formatter_test.cpp)
target_link_libraries(sql_formatter_test PRIVATE replicapulse)
add_test(NAME sql_formatter_test COMMAND sql_formatter_test)

add_executable(parser_tolerance_test tests/parser_tolerance_test.cpp)
target_link_libraries(parser_tolerance_test PRIVATE replicapulse)
add_test(NAME parser_tolerance_test COMMAND parser_tolerance_test)

add_executable(type_roundtrip_test tests/type_roundtrip_test.cpp)
target_link_libraries(type_roundtrip_test PRIVATE replicapulse)
add_test(NAME type_roundtrip_test COMMAND type_roundtrip_test)

add_executable(ordering_checkpoint_test tests/ordering_checkpoint_test.cpp)
target_link_libraries(ordering_checkpoint_test PRIVATE replicapulse)
add_test(NAME ordering_checkpoint_test COMMAND ordering_checkpoint_test)

add_executable(update_rows_decode_test tests/update_rows_decode_test.cpp)
target_link_libraries(update_rows_decode_test PRIVATE replicapulse)
add_test(NAME update_rows_decode_test COMMAND update_rows_decode_test)

add_executable(previous_gtids_test tests/previous_gtids_test.cpp)
target_link_libraries(previous_gtids_test PRIVATE replicapulse)
add_test(NAME previous_gtids_test COMMAND previous_gtids_test)

add_executable(ddl_invalidation_test tests/ddl_invalidation_test.cpp)
target_link_libraries(ddl_invalidation_test PRIVATE replicapulse)
add_test(NAME ddl_invalidation_test COMMAND ddl_invalidation_test)

add_executable(binlog_checksum_test tests/binlog_checksum_test.cpp)
target_link_libraries(binlog_checksum_test PRIVATE replicapulse)
add_test(NAME binlog_checksum_test COMMAND binlog_checksum_test)

add_executable(gtid_set_merge_test tests/gtid_set_merge_test.cpp)
target_link_libraries(gtid_set_merge_test PRIVATE replicapulse)
add_test(NAME gtid_set_merge_test COMMAND gtid_set_merge_test)

add_executable(gtid_tracker_commit_test tests/gtid_tracker_commit_test.cpp)
target_link_libraries(gtid_tracker_commit_test PRIVATE replicapulse)
add_test(NAME gtid_tracker_commit_test COMMAND gtid_tracker_commit_test)

add_executable(output_sink_test tests/output_sink_test.cpp)
target_link_libraries(output_sink_test PRIVATE replicapulse)
add_test(NAME output_sink_test COMMAND output_sink_test)

add_executable(optimization_test tests/optimization_test.cpp)
target_link_libraries(optimization_test PRIVATE replicapulse)
add_test(NAME optimization_test COMMAND optimization_test)
