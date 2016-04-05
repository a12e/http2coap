/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 * -*- */

/* coap_list.c -- CoAP list structures
 *
 * Copyright (C) 2010,2011,2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms of
 * use.
 */

/* #include "coap_config.h" */

#include "coap_list.h"

int
coap_insert(coap_list_t **head, coap_list_t *node) {
    if (!node) {
        coap_log(LOG_WARNING, "cannot create option Proxy-Uri\n");
    } else {
        /* must append at the list end to avoid re-ordering of
         * options during sort */
        LL_APPEND((*head), node);
    }

    return node != NULL;
}

int
coap_delete(coap_list_t *node) {
    if (node) {
        coap_free(node);
    }
    return 1;
}

void
coap_delete_list(coap_list_t *queue) {
    coap_list_t *elt, *tmp;

    if (!queue)
        return;

    LL_FOREACH_SAFE(queue, elt, tmp) {
        coap_delete(elt);
    }
}

coap_list_t *new_option_node(unsigned short key, unsigned int length, unsigned char *data) {
    coap_list_t *node;

    node = coap_malloc(sizeof(coap_list_t) + sizeof(coap_option) + length);

    if (node) {
        coap_option *option;
        option = (coap_option *)(node->data);
        COAP_OPTION_KEY(*option) = key;
        COAP_OPTION_LENGTH(*option) = length;
        memcpy(COAP_OPTION_DATA(*option), data, length);
    } else {
        coap_log(LOG_DEBUG, "new_option_node: malloc\n");
    }

    return node;
}