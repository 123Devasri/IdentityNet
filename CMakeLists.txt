cmake_minimum_required(VERSION 3.10)
project(IdentityNet C)

set(CMAKE_C_STANDARD 11)

include_directories(src wfp)

set(SOURCES
    src/main.c
    src/network.c
    src/policy.c
    src/clients.c
    src/logger.c
    src/dns_server.c
    src/contest_server.c
    wfp/wfp_manager.c
)

add_executable(IdentityNet ${SOURCES})

target_link_libraries(IdentityNet PRIVATE ws2_32 iphlpapi)
