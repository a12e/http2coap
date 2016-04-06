#ifndef HTTP2COAP_HTTP_SERVER_H
#define HTTP2COAP_HTTP_SERVER_H

#include <microhttpd.h>
#include <coap/pdu.h>

extern struct MHD_Daemon *http_daemon;
extern char static_files_path[64];
extern struct sockaddr_in destination;

void start_http_server(uint16_t port);

int send_simple_http_response(struct MHD_Connection *connection, unsigned int status_code, const char *data);
int coap_abort_to_http(struct MHD_Connection *connection, const char *message);

typedef struct {
    struct MHD_Connection *connection;
    coap_tid_t transaction_id;
} http_coap_pair_t;
#define MAX_HTTP_CONNECTIONS 64
extern http_coap_pair_t http_coap_pairs[MAX_HTTP_CONNECTIONS];

#endif //HTTP2COAP_HTTP_SERVER_H
