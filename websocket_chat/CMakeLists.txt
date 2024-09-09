
add_executable(ws_srv)

FILE(GLOB ws_srv_SRCS "*.cpp")

target_sources(ws_srv PRIVATE ${ws_srv_SRCS})

target_include_directories(ws_srv PRIVATE ${libevent_SOURCE_DIR})

set_property(TARGET ws_srv PROPERTY CXX_STANDARD 17)
target_link_libraries(ws_srv PUBLIC event_core_static event_static )