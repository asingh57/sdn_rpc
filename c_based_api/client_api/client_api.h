#include <coap2/coap.h>


struct Address_info{
    char *interface_addr;
    char *port;
};


void coap_init(struct Address_info **client_details, int client_count, struct Address_info dest_info);

int resolve_address(const char *host, const char *service, coap_address_t *dst);//resolves a address given as char array and parses it for aiocoap




struct Sessions{
    coap_context_t  *ctx;
    coap_session_t **sessions;
    coap_address_t dst;
    coap_pdu_t *pdu;
};


