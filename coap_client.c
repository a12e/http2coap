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
    fprintf(stderr, "Resolved %s: %s port %u\n", server->s,
            inet_ntoa(((struct sockaddr_in*)dst)->sin_addr),
            ntohs(((struct sockaddr_in*)dst)->sin_port));
    freeaddrinfo(res);
    return len;
}

coap_context_t *get_context(const char *node, const char *port)
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

static coap_pdu_t *coap_new_request(coap_context_t *ctx, method_t m, coap_list_t **options,
                                    unsigned char *data, size_t length) {
    coap_pdu_t *pdu;
    coap_list_t *opt;

    if ( ! ( pdu = coap_new_pdu() ) )
        return NULL;

    pdu->hdr->type = msgtype;
    pdu->hdr->id = coap_new_message_id(ctx);
    pdu->hdr->code = m;

    pdu->hdr->token_length = the_token.length;
    if ( !coap_add_token(pdu, the_token.length, the_token.s)) {
        debug("cannot add token to request\n");
    }

    coap_show_pdu(pdu);

    if (options) {
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

    if (length) {
        if ((flags & FLAGS_BLOCK) == 0)
            coap_add_data(pdu, length, data);
        else
            coap_add_block(pdu, length, data, block.num, block.szx);
    }

    return pdu;
}