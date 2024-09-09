include(FetchContent)

FetchContent_Declare(
    libevent
    GIT_REPOSITORY https://github.com/avble/libevent.git
    GIT_TAG        master
)

if(NOT libevent_POPULATED)
  FetchContent_Populate(libevent)
  option(EVENT__DISABLE_SAMPLES "" ON)
  option(EVENT_LIBRARY_STATIC "" ON)
  option(EVENT_LIBRARY_SHARED "" OFF)
  option(EVENT__DISABLE_TESTS "" ON)
  option(EVENT__DISABLE_BENCHMARK "" ON)
  add_subdirectory(${libevent_SOURCE_DIR} ${libevent_BINARY_DIR})
endif()