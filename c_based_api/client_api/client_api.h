#include <coap2/coap.h>
#include "../common/common.h"

struct Address_info{
    char *interface_addr;
    char *port;
};


void coap_client_init(struct Address_info **client_details, int client_count, struct Server_address_info dest_info);

struct Sessions{
    coap_context_t  *ctx;
    coap_session_t **sessions;
    coap_address_t dst;
    coap_pdu_t *pdu;
};


