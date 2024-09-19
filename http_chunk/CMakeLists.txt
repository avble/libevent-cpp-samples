add_executable(http_srv_chunk)

FILE(GLOB http_srv_chunk_SRCS "http_chunk.cpp")

target_sources(http_srv_chunk PRIVATE ${http_srv_chunk_SRCS})

target_include_directories(http_srv_chunk PRIVATE ${libevent_SOURCE_DIR})

set_property(TARGET http_srv_chunk PROPERTY CXX_STANDARD 17)
target_link_libraries(http_srv_chunk PUBLIC event_static event_core_static)