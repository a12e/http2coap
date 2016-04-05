#include <stdio.h>
#include <arpa/inet.h>
#include "http_server.h"
#include "coap_client.h"

struct MHD_Daemon *http_daemon = NULL;
static int http_request_handler(void *cls, struct MHD_Connection *connection, const char *url, const char *method,
                         const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls);
// These pairs are necessary to know to which connection we need to send the HTTP response when receiving a CoAP response
http_coap_pair_t http_coap_pairs[MAX_HTTP_CONNECTIONS];
// Where we need to send our CoAP requests
struct sockaddr_in destination;

void start_http_server(uint16_t port) {
    http_daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, port, NULL, NULL,
                                   http_request_handler, NULL, MHD_OPTION_END);
    memset(&http_coap_pairs, 0, sizeof(http_coap_pairs));
}

// Little wrapper for sending simple text responses
int send_simple_http_response(struct MHD_Connection *connection, unsigned int status_code, const char *data) {
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(data), (void *)data, MHD_RESPMEM_PERSISTENT);
    int res = MHD_queue_response(connection, status_code, response);
    MHD_destroy_response(response);
    const struct sockaddr_in *client_addr = (const struct sockaddr_in *)
            MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS)->client_addr;
    printf("HTTP %13s:%-5u <- %u\n", inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port), status_code);
    return res;
}

// Ouptut an error to stderr and send en HTTP response too
int coap_abort_to_http(struct MHD_Connection *connection, const char *message) {
    fputs(message, stderr);
    return send_simple_http_response(connection, MHD_HTTP_BAD_GATEWAY, message);
}

// Where HTTP requests are processed
static int http_request_handler(void *cls, struct MHD_Connection *connection, const char *url, const char *method,
                                const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls) {
    // Check if we already handled this connection
    if(*con_cls == connection)
        return MHD_YES;
    else
        *con_cls = connection;

    const struct sockaddr_in *client_addr = (const struct sockaddr_in *)
            MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS)->client_addr;
    printf("HTTP %13s:%-5u -> %s %s\n", inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port), method, url);

    // Define Method
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

    // Add URI if any
    coap_list_t *options_list = NULL;
    if(strlen(url) - 1 > 0) {
#define BUFSIZE 40
        unsigned char _buf[BUFSIZE];
        unsigned char *buf = _buf;
        size_t buflen = BUFSIZE;
        int res = coap_split_query((const unsigned char *)url + 1, strlen(url) - 1, buf, &buflen);

        while(res--) {
            coap_insert(&options_list, new_option_node(COAP_OPTION_URI_PATH,
                                                       COAP_OPT_LENGTH(buf), COAP_OPT_VALUE(buf)));
            buf += COAP_OPT_SIZE(buf);
        }
    }

    // Create packet
    coap_pdu_t *pdu;
    if(!(pdu = coap_new_request(coap_context, coap_method, &options_list, NULL, 0)))
        coap_abort_to_http(connection, "coap_new_request failed");

    // Create destination address
    coap_address_t destination_address;
    memcpy(&destination_address.addr.sin, &destination, sizeof(destination));
    destination_address.size = sizeof(destination);

    printf("COAP %13s:%-5u <- ",
           inet_ntoa((&destination_address.addr.sin)->sin_addr),
           ntohs((&destination_address.addr.sin)->sin_port));
    coap_show_pdu(pdu);

    // Send the message to the queue
    coap_tid_t transaction_id;
    if((transaction_id = coap_send_confirmed(coap_context, coap_context->endpoint, &destination_address, pdu))
       == COAP_INVALID_TID)
        return coap_abort_to_http(connection, "coap_send_confirmed failed");

    // Keep a trace of this HTTP connection so we can send the response later
    for(int i = 0; i < MAX_HTTP_CONNECTIONS; i++) {
        if(http_coap_pairs[i].connection == NULL) {
            http_coap_pairs[i].connection = connection;
            http_coap_pairs[i].transaction_id = transaction_id;
            break;
        }
    }

    fd_set readfds;
    coap_tick_t now;
    coap_queue_t *next_pdu;

    unsigned int wait_seconds = 10;         /* default timeout in seconds */
    coap_tick_t max_wait;                   /* global timeout (changed by set_timeout()) */
    coap_ticks(&max_wait);
    max_wait += wait_seconds * COAP_TICKS_PER_SECOND;

    // while there are messages to dispatch
    while(!coap_can_exit(coap_context)) {
        FD_ZERO(&readfds);
        FD_SET(coap_context->sockfd, &readfds);

        next_pdu = coap_peek_next(coap_context);

        coap_ticks(&now);
        while (next_pdu && next_pdu->t <= now - coap_context->sendqueue_basetime) {
            printf("COAP %13s:%-5u <- (retransmit) ",
                   inet_ntoa((&destination_address.addr.sin)->sin_addr),
                   ntohs((&destination_address.addr.sin)->sin_port));
            coap_show_pdu(pdu);

            coap_retransmit(coap_context, coap_pop_next(coap_context));
            next_pdu = coap_peek_next(coap_context);
        }

        // Now wait for responses for 5 seconds
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;

        int result = select(coap_context->sockfd + 1, &readfds, 0, 0, &tv);

        if(result < 0) {   /* error */
            perror("select");
        }
        else if(result > 0) {  /* read from socket */
            if(FD_ISSET(coap_context->sockfd, &readfds)) {
                coap_read(coap_context);       /* read received data */
            }
            else {
                fprintf(stderr, "not reading since not the right socket\n");
            }
        }
        else { /* timeout */
            fprintf(stderr, "select timeout\n");
            coap_ticks(&now);
            if(max_wait <= now) {
                fprintf(stderr, "TIMEOUT\n");
                break;
            }
        }
    }

    return MHD_YES; // the connection was handled successfully,
}