#include <cjson/cJSON.h>

#include "../../server_api/server_api.h"

int main(){
    

    
    char server_ip[16] = "127.0.0.1";
    char server_port[16] = "5000";

    char server_ip2[16] = "127.0.0.1";
    char server_port2[16] = "5000";

    struct Server_address_info **coap_servers= malloc(sizeof(struct Server_address_info*)*2);
    struct Server_address_info server, server2;    
    coap_servers[0]=&server;
    coap_servers[1]=&server2;
    server.interface_addr=server_ip;
    server.port=server_port;
    server.uri=strdup("aaa");
    server2.interface_addr=server_ip2;
    server2.port=server_port2;
    server2.uri=strdup("aaa");

    coap_server_init(coap_servers,2);
    


    
    return 0;
}
