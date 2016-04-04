#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <microhttpd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <signal.h>
#include <coap/pdu.h>
#include "coap_client.h"

static struct sockaddr_in destination = {};
struct MHD_Daemon *http_daemon = NULL;
static coap_context_t *coap_context = NULL;
typedef struct {
    struct MHD_Connection *connection;
    coap_tid_t transaction_id;
} http_coap_pair_t;
#define MAX_CONNECTIONS 64
http_coap_pair_t http_coap_pairs[MAX_CONNECTIONS];

int send_simple_http_response(struct MHD_Connection *connection, unsigned int status_code, const char *data) {
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(data), (void *)data, MHD_RESPMEM_PERSISTENT);
    int res = MHD_queue_response(connection, status_code, response);
    MHD_destroy_response(response);
    const struct sockaddr_in *client_addr = (const struct sockaddr_in *)
            MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS)->client_addr;
    printf("HTTP %13s:%-5u <- %u\n", inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port), status_code);
    return res;
}

int abort_coap(struct MHD_Connection *connection, const char *message) {
    fprintf(stderr, message);
    return send_simple_http_response(connection, MHD_HTTP_BAD_GATEWAY, message);
}

/** Returns a textual description of the method or response code. */
static const char *
msg_code_string(uint8_t c) {
    static char *methods[] = { "0.00", "GET", "POST", "PUT", "DELETE", "PATCH" };
    static char buf[5];

    if (c < sizeof(methods)/sizeof(char *)) {
        return methods[c];
    } else {
        snprintf(buf, sizeof(buf), "%u.%02u", c >> 5, c & 0x1f);
        return buf;
    }
}

#undef MHD_get_reason_phrase_for
_MHD_EXTERN const char *MHD_get_reason_phrase_for(unsigned int code);

void coap_response_handler(struct coap_context_t *ctx, const coap_endpoint_t *local_interface,
                           const coap_address_t *remote, coap_pdu_t *sent, coap_pdu_t *received, const coap_tid_t id) {
    printf("COAP %13s:%-5u -> ",
           inet_ntoa((&remote->addr.sin)->sin_addr),
           ntohs((&remote->addr.sin)->sin_port));
    coap_show_pdu(received);

    for(int i = 0; i < MAX_CONNECTIONS; i++) {
        if(http_coap_pairs[i].transaction_id == id) {
            struct MHD_Connection *connection = http_coap_pairs[i].connection;
            size_t len;
            unsigned char *databuf;

            if(coap_get_data(received, &len, &databuf) == 0) {
                // error when reading the data
                abort_coap(connection, "coap_get_data error");
            }
            else {
                struct MHD_Response *response = MHD_create_response_from_buffer(len, databuf, MHD_RESPMEM_MUST_COPY);

                char tid_str[8];
                snprintf(tid_str, 8, "%u", ntohs(received->hdr->id));
                MHD_add_response_header(response, "X-CoAP-Message-Id", tid_str);
                MHD_add_response_header(response, "X-CoAP-Response-Code", msg_code_string(received->hdr->code));

                unsigned int http_status_code = (received->hdr->code >> 5) * 100 + (received->hdr->code & 0x1f);
                MHD_queue_response(connection, http_status_code, response);
                MHD_destroy_response(response);

                const struct sockaddr_in *client_addr = (const struct sockaddr_in *)
                        MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS)->client_addr;
                printf("HTTP %13s:%-5u <- %u %s\n", inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port),
                       http_status_code, MHD_get_reason_phrase_for(http_status_code));
            }

            // clear the association
            http_coap_pairs[i].connection = NULL;
            http_coap_pairs[i].transaction_id = COAP_INVALID_TID;
            break;
        }
    }
}

static int http_request_handler(void *cls, struct MHD_Connection *connection, const char *url, const char *method,
                                const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls) {
    // Check if we already handled this connection
    if(*con_cls == connection) {
        return MHD_YES;
    }
    else {
        *con_cls = connection;
    }

    const struct sockaddr_in *client_addr = (const struct sockaddr_in *)
            MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS)->client_addr;
        printf("HTTP %13s:%-5u -> %s %s\n", inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port), method, url);

    // 1. Méthode
    method_t coap_method;
    if(strcmp(MHD_HTTP_METHOD_GET, method) == 0) {
        coap_method = COAP_REQUEST_GET;
    }
    else if(strcmp(MHD_HTTP_METHOD_POST, method) == 0) {
        coap_method = COAP_REQUEST_POST;
    }
    else if(strcmp(MHD_HTTP_METHOD_PUT, method) == 0) {
        coap_method = COAP_REQUEST_PUT;
    }
    else if(strcmp(MHD_HTTP_METHOD_DELETE, method) == 0) {
        coap_method = COAP_REQUEST_DELETE;
    }
    else {
        return send_simple_http_response(connection, MHD_HTTP_NOT_ACCEPTABLE, "You can't use this method in CoAP");
    }

    // CRÉATION DE LA REQUÊTE COAP
    coap_pdu_t *pdu;
    if(!(pdu = coap_new_request(coap_context, coap_method, NULL, (unsigned char *)url, strlen(url))))
        abort_coap(connection, "coap_new_request failed");

    coap_address_t destination_address;
    memcpy(&destination_address.addr.sin, &destination, sizeof(destination));
    destination_address.size = sizeof(destination);

    printf("COAP %13s:%-5u <- ",
           inet_ntoa((&destination_address.addr.sin)->sin_addr),
           ntohs((&destination_address.addr.sin)->sin_port));
    coap_show_pdu(pdu);

    coap_tid_t transaction_id;
    if((transaction_id = coap_send_confirmed(coap_context, coap_context->endpoint, &destination_address, pdu))
       == COAP_INVALID_TID)
        return abort_coap(connection, "coap_send_confirmed failed");

    for(int i = 0; i < MAX_CONNECTIONS; i++) {
        if(http_coap_pairs[i].connection == NULL) {
            http_coap_pairs[i].connection = connection;
            http_coap_pairs[i].transaction_id = transaction_id;
            break;
        }
    }

    if(read(coap_context->sockfd, NULL, 0) == -1) {
        perror("read");
        return abort_coap(connection, "read failed");
    }

    if(coap_read(coap_context) != 0)
        return abort_coap(connection, "coap_read failed");

    return MHD_YES; // the connection was handled successfully,
}

static void signal_handler(int signo) {
    fprintf(stderr, "Exiting\n");
    if(coap_context) coap_free_context(coap_context); coap_context = NULL;
    if(http_daemon) MHD_stop_daemon(http_daemon); http_daemon = NULL;
}

int main(int argc, char *argv[])
{
    int c;
    str target_hostname;
    int server_port = 8080;
    while((c = getopt(argc, argv, "d:hp:")) != EOF) {
        switch(c) {
            case 'd':
                target_hostname.s = (unsigned char *)optarg;
                target_hostname.length = strlen(optarg);
                resolve_address(&target_hostname, (struct sockaddr *)&destination);
                destination.sin_port = htons(5683);
                break;
            case 'h':
                fprintf(stderr, "usage: %s", argv[0]);
                break;
            case 'p':
                server_port = atoi(optarg);
                assert(server_port > 0 && server_port <= UINT16_MAX);
                break;
            default:
                fprintf(stderr, "unrecognized option %c\n", c);
        }
    }

    if(signal(SIGTERM, signal_handler) == SIG_ERR) {
        fprintf(stderr, "An error occurred while setting a signal handler.\n");
        return EXIT_FAILURE;
    }

    memset(&http_coap_pairs, 0, sizeof(http_coap_pairs));

    http_daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, (uint16_t) server_port, NULL, NULL,
                                   http_request_handler, NULL, MHD_OPTION_END);
    if(http_daemon == NULL) {
        fprintf(stderr, "HTTP server failed to start: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    fprintf(stderr, "HTTP server is running on port %u\n", server_port);

    // CRÉATION DU CONTEXTE
    coap_set_log_level(LOG_DEBUG);
    coap_context = create_coap_context(NULL, "5683");
    coap_register_response_handler(coap_context, coap_response_handler);

    (void)getchar();

    return EXIT_SUCCESS;
}