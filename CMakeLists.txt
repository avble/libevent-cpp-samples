cmake_minimum_required(VERSION 3.16)

project(libevent_sample_cpp 
    LANGUAGES CXX)

include(external.cmake)

add_subdirectory(http)
add_subdirectory(websocket_chat)
