#include <stdio.h>
#include <arpa/inet.h>
#include "coap_handler.h"
#include "http_server.h"
#include "http_reason_phrases.h"

/** Returns a textual description of the method or response code. */
static const char *msg_code_string(uint8_t c) {
    static char *methods[] = { "0.00", "GET", "POST", "PUT", "DELETE", "PATCH" };
    static char buf[5];

    if (c < sizeof(methods)/sizeof(char *)) {
        return methods[c];
    } else {
        snprintf(buf, sizeof(buf), "%u.%02u", c >> 5, c & 0x1f);
        return buf;
    }
}

// When we receive the CoAP response we build and send the HTTP response
void coap_response_handler(struct coap_context_t *ctx, const coap_endpoint_t *local_interface,
                           const coap_address_t *remote, coap_pdu_t *sent, coap_pdu_t *received, const coap_tid_t id) {
    printf("COAP %13s:%-5u -> ",
           inet_ntoa((&remote->addr.sin)->sin_addr),
           ntohs((&remote->addr.sin)->sin_port));
    coap_show_pdu(received);

    for(int i = 0; i < MAX_HTTP_CONNECTIONS; i++) {
        if(http_coap_pairs[i].transaction_id == id) {
            struct MHD_Connection *connection = http_coap_pairs[i].connection;
            size_t len;
            unsigned char *databuf;

            if(coap_get_data(received, &len, &databuf) == 0) {
                // error when reading the data
                coap_abort_to_http(connection, "coap_get_data error");
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
                        coap_abort_to_http(connection, "coap_opt_parse error");
                    }
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
                       http_code, http_reason_phrase_for(http_code));
            }

            // clear the association
            http_coap_pairs[i].connection = NULL;
            http_coap_pairs[i].transaction_id = COAP_INVALID_TID;
            break;
        }
    }
}