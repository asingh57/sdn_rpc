#include <coap2/coap.h>
#include "../common/common.h"



typedef struct Servers{
    struct coap_context_t  *ctx;//one context
    struct coap_endpoint_t **eps;
    struct coap_resource_t **res;
    struct coap_pdu_t *pdu;
} Servers;



void coap_server_init(struct Server_address_info **server_details, int server_count);

