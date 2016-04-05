#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <microhttpd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <signal.h>
#include <coap/pdu.h>
#include <pthread.h>
#include <coap/option.h>
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

                // HTTP Content-Type
                coap_opt_t *option_string;
                coap_option_t option;
                coap_opt_iterator_t option_iterator;
                if((option_string = coap_check_option(received, COAP_OPTION_CONTENT_FORMAT, &option_iterator))) {
                    if(!coap_opt_parse(option_string, 64, &option)) {
                        abort_coap(connection, "coap_opt_parse error");
                    }
                    fprintf(stderr, "len = %zu\n", option.length);
                }

                // HTTP Code
                unsigned int http_code;
                switch(received->hdr->code) {
                    case COAP_RESPONSE_200:         http_code = MHD_HTTP_OK;                    break; /* 2.00 OK */
                    case COAP_RESPONSE_201:         http_code = MHD_HTTP_CREATED;               break; /* 2.01 Created */
                    case COAP_RESPONSE_CODE(205):   http_code = MHD_HTTP_OK;                    break;
                    case COAP_RESPONSE_304:         http_code = MHD_HTTP_ACCEPTED;              break; /* 2.03 Valid */
                    case COAP_RESPONSE_400:         http_code = MHD_HTTP_BAD_REQUEST;           break; /* 4.00 Bad Request */
                    case COAP_RESPONSE_404:         http_code = MHD_HTTP_NOT_FOUND;             break; /* 4.04 Not Found */
                    case COAP_RESPONSE_405:         http_code = MHD_HTTP_NOT_ACCEPTABLE;        break; /* 4.05 Method Not Allowed */
                    case COAP_RESPONSE_415:         http_code = MHD_HTTP_UNSUPPORTED_MEDIA_TYPE;break; /* 4.15 Unsupported Media Type */
                    case COAP_RESPONSE_500:         http_code = MHD_HTTP_INTERNAL_SERVER_ERROR; break; /* 5.00 Internal Server Error */
                    case COAP_RESPONSE_501:         http_code = MHD_HTTP_NOT_IMPLEMENTED;       break; /* 5.01 Not Implemented */
                    case COAP_RESPONSE_503:         http_code = MHD_HTTP_SERVICE_UNAVAILABLE;   break; /* 5.03 Service Unavailable */
                    case COAP_RESPONSE_504:         http_code = MHD_HTTP_GATEWAY_TIMEOUT;       break; /* 5.04 Gateway Timeout */
                    default:                        http_code = MHD_HTTP_INTERNAL_SERVER_ERROR; break;
                }
                MHD_queue_response(connection, http_code, response);
                MHD_destroy_response(response);

                const struct sockaddr_in *client_addr = (const struct sockaddr_in *)
                        MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS)->client_addr;
                printf("HTTP %13s:%-5u <- %u %s\n", inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port),
                       http_code, MHD_get_reason_phrase_for(http_code));
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
        fprintf(stderr, "aborted since already handled\n");
        return MHD_YES;
    }
    else {
        *con_cls = connection;
    }

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
        abort_coap(connection, "coap_new_request failed");

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
        return abort_coap(connection, "coap_send_confirmed failed");

    // Keep a trace of this HTTP connection so we can send the response later
    for(int i = 0; i < MAX_CONNECTIONS; i++) {
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

        fprintf(stderr, "All messages are sent, waiting response...\n");

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
                fprintf(stderr, "reading CoAP\n");
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

    fprintf(stderr, "end of http_request_handler\n");

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

    http_daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, (uint16_t)server_port, NULL, NULL,
                                   http_request_handler, NULL, MHD_OPTION_END);
    if(http_daemon == NULL) {
        fprintf(stderr, "HTTP server failed to start: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    fprintf(stderr, "HTTP server is listening on port %u (using libmicrohttpd %s)\n", server_port, MHD_get_version());

    // CRÉATION DU CONTEXTE
    coap_set_log_level(LOG_DEBUG);
    coap_context = coap_create_context("0.0.0.0", NULL);
    coap_register_response_handler(coap_context, coap_response_handler);

    (void)getchar();

    return EXIT_SUCCESS;
}