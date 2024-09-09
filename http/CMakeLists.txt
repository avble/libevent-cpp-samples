
add_executable(http_srv)

FILE(GLOB http_srv_SRCS "*.cpp")

target_sources(http_srv PRIVATE ${http_srv_SRCS})

target_include_directories(http_srv PRIVATE ${libevent_SOURCE_DIR})

set_property(TARGET http_srv PROPERTY CXX_STANDARD 17)
target_link_libraries(http_srv PUBLIC event_static event_core_static)