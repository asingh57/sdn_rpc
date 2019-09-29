#include <coap2/coap.h>

struct Server_address_info{
    char *interface_addr;
    char *port;
    char *uri;
};


int resolve_address(const char *host, const char *service, coap_address_t *dst);//resolves a address given as char array and parses it for aiocoap

