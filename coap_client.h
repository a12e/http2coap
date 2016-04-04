#ifndef HTTP2COAP_COAP_CLIENT_H
#define HTTP2COAP_COAP_CLIENT_H

#include <coap/coap.h>
#include "coap_list.h"

int resolve_address(const str *server, struct sockaddr *dst);
coap_context_t *get_context(const char *node, const char *port);

typedef unsigned char method_t;
static coap_pdu_t *coap_new_request(coap_context_t *ctx, method_t m, coap_list_t **options,
                                    unsigned char *data, size_t length);

#endif //HTTP2COAP_COAP_CLIENT_H
