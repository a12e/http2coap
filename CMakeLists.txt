cmake_minimum_required(VERSION 3.3)
project(http2coap)
set(CMAKE_C_STANDARD 99)
add_definitions("-Wall -Wextra -DWITH_POSIX")

set(SOURCE_FILES main.c coap_client.c coap_client.h coap_list.c coap_list.h http_reason_phrases.c http_reason_phrases.h http_server.c http_server.h coap_handler.c coap_handler.h)
add_executable(http2coap ${SOURCE_FILES})

target_link_libraries(http2coap microhttpd coap-1)