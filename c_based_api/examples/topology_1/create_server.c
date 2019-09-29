#include <cjson/cJSON.h>

#include "../../server_api/server_api.h"

int main(){
    

    
    char server_ip[16] = "127.0.0.1";
    char server_port[16] = "5000";
    struct Server_address_info **coap_servers= malloc(sizeof(struct Server_address_info*)*1);
    struct Server_address_info server;
    coap_servers[0]=&server;
    server.interface_addr=server_ip;
    server.port=server_port;
    server.uri=strdup("aaa");
    coap_server_init(coap_servers,1);
    


    
    return 0;
}
