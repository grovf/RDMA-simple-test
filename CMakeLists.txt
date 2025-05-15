cmake_minimum_required(VERSION 3.10)
project(rdma_simple_test)

add_executable(rdma_simple_test main.cpp)

target_link_libraries(rdma_simple_test PUBLIC ibverbs)