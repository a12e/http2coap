#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <microhttpd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include "coap_client.h"

static struct sockaddr_in destination;

static int answer_to_connection(void *cls, struct MHD_Connection *connection, const char *url, const char *method,
                      const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls)
{
    printf("-> %s %s\n", method, url);

    // CRÉATION DU CONTEXTE
    coap_context_t *ctx = get_context(NULL, "5683");
    fprintf(stderr, "Context has IP %s port %u\n",
            inet_ntoa((&ctx->endpoint->addr.addr.sin)->sin_addr),
            ntohs((&ctx->endpoint->addr.addr.sin)->sin_port));

    // CRÉATION D'UN PDU
    coap_pdu_t *pdu;
    const char *data = "Bonjour !";
    if(!(pdu = coap_pdu_init(COAP_MESSAGE_CON, 200, 999, strlen(data) + sizeof(coap_hdr_t) + 16))) {
        fprintf(stderr, "coap_pdu_init failed\n");
        return MHD_HTTP_INTERNAL_SERVER_ERROR;
    }

    if(coap_add_data(pdu, (unsigned int)strlen(data) + 1, (const unsigned char *)data) == 0) {
        fprintf(stderr, "coap_add_data failed\n");
        return MHD_HTTP_INTERNAL_SERVER_ERROR;
    }

    coap_address_t destination_address;
    memcpy(&destination_address.addr.sin, &destination, sizeof(destination));
    destination_address.size = sizeof(destination);

    fprintf(stderr, "Sending CoAP request to %s port %u (addr size = %u)\n",
            inet_ntoa((&destination_address.addr.sin)->sin_addr),
            ntohs((&destination_address.addr.sin)->sin_port),
            destination_address.size);

    if(coap_send_confirmed(ctx, ctx->endpoint, &destination_address, pdu) == COAP_INVALID_TID) {
        fprintf(stderr, "coap_send_confirmed failed\n");
        return MHD_HTTP_INTERNAL_SERVER_ERROR;
    }

    //coap_delete_pdu(pdu);
    //coap_free_context(ctx);

    const char *page = "<html><body>Hello, browser!</body></html>";
    struct MHD_Response *response;
    int ret;

    response = MHD_create_response_from_buffer(strlen(page), (void *)page, MHD_RESPMEM_PERSISTENT);
    ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);

    return ret;
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

    struct MHD_Daemon *daemon;

    daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, (uint16_t) server_port, NULL, NULL,
                              answer_to_connection, NULL, MHD_OPTION_END);
    if (daemon == NULL) {
        fprintf(stderr, "HTTP server failed to start: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    fprintf(stderr, "HTTP server is running on port %u\n", server_port);

    (void)getchar();

    MHD_stop_daemon(daemon);

    return EXIT_SUCCESS;
}