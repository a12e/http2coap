#include <netdb.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <coap/str.h>
#include "coap_client.h"

int resolve_address(const str *server, struct sockaddr *dst) {

    struct addrinfo *res, *ainfo;
    struct addrinfo hints;
    static char addrstr[256];
    int error, len=-1;

    memset(addrstr, 0, sizeof(addrstr));
    if(server->length)
        memcpy(addrstr, server->s, server->length);
    else
        memcpy(addrstr, "localhost", 9);

    memset ((char *)&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;

    error = getaddrinfo(addrstr, NULL, &hints, &res);

    if (error != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
        return error;
    }

    for(ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {
        switch (ainfo->ai_family) {
            case AF_INET6:
            case AF_INET:
                len = ainfo->ai_addrlen;
                memcpy(dst, ainfo->ai_addr, len);
                goto finish;
            default:
                ;
        }
    }

    finish:
    freeaddrinfo(res);
    return len;
}

coap_context_t *create_coap_context(const char *node, const char *port)
{
    coap_context_t *ctx = NULL;
    int s;
    struct addrinfo hints;
    struct addrinfo *result, *rp;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Coap uses UDP */
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV | AI_ALL;

    s = getaddrinfo(node, port, &hints, &result);
    if ( s != 0 ) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        return NULL;
    }

    /* iterate through results until success */
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        coap_address_t addr;

        if (rp->ai_addrlen <= sizeof(addr.addr)) {
            coap_address_init(&addr);
            addr.size = rp->ai_addrlen;
            memcpy(&addr.addr, rp->ai_addr, rp->ai_addrlen);

            ctx = coap_new_context(&addr);
            if (ctx) {
                fprintf(stderr, "CoAP context created on %s port %u\n",
                        inet_ntoa(((struct sockaddr_in*)rp->ai_addr)->sin_addr),
                        ntohs(((struct sockaddr_in*)rp->ai_addr)->sin_port));
                goto finish;
            }
        }
    }

    fprintf(stderr, "no context available for interface '%s'\n", node);

    finish:
    freeaddrinfo(result);
    return ctx;
}

static int order_opts(void *a, void *b) {
    coap_option *o1, *o2;

    if (!a || !b)
        return a < b ? -1 : 1;

    o1 = (coap_option *)(((coap_list_t *)a)->data);
    o2 = (coap_option *)(((coap_list_t *)b)->data);

    return (COAP_OPTION_KEY(*o1) < COAP_OPTION_KEY(*o2))
           ? -1
           : (COAP_OPTION_KEY(*o1) != COAP_OPTION_KEY(*o2));
}

static unsigned char _token_data[8];
unsigned char msgtype = COAP_MESSAGE_CON; /* usually, requests are sent confirmable */
str the_token = { 0, _token_data };

coap_pdu_t *coap_new_request(coap_context_t *ctx, method_t m, coap_list_t **options, unsigned char *data, size_t length) {
    coap_pdu_t *pdu;
    coap_list_t *opt;

    if(!(pdu = coap_new_pdu())) {
        fprintf(stderr, "coap_new_pdu failed\n");
        return NULL;
    }

    pdu->hdr->type = msgtype;
    pdu->hdr->id = coap_new_message_id(ctx);
    pdu->hdr->code = m;

    pdu->hdr->token_length = (unsigned int)the_token.length;
    if(!coap_add_token(pdu, the_token.length, the_token.s)) {
        fprintf(stderr, "cannot add token to request\n");
    }


    if(options) {
        /* sort options for delta encoding */
        LL_SORT((*options), order_opts);

        LL_FOREACH((*options), opt) {
            coap_option *o = (coap_option *)(opt->data);
            coap_add_option(pdu,
                            COAP_OPTION_KEY(*o),
                            COAP_OPTION_LENGTH(*o),
                            COAP_OPTION_DATA(*o));
        }
    }

    if(length) {
        coap_add_data(pdu, (unsigned int)length, data);
    }

    return pdu;
}