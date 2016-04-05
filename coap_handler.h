#ifndef HTTP2COAP_COAP_HANDLER_H
#define HTTP2COAP_COAP_HANDLER_H

#include <coap/coap.h>

void coap_response_handler(struct coap_context_t *ctx, const coap_endpoint_t *local_interface,
                           const coap_address_t *remote, coap_pdu_t *sent, coap_pdu_t *received, const coap_tid_t id);

#endif //HTTP2COAP_COAP_HANDLER_H
