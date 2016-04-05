#ifndef HTTP2COAP_HTTP_REASON_PHRASES_H
#define HTTP2COAP_HTTP_REASON_PHRASES_H

// This is a copy of MHD_get_reason_phrase_for() because it is not exported by the lib
const char *http_reason_phrase_for(unsigned int code);

#endif //HTTP2COAP_HTTP_REASON_PHRASES_H
