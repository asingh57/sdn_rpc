#include <cjson/cJSON.h>
#include "../../client_api/client_api.h"

int main(){
    

    
    char server_ip[16] = "127.0.0.1";
    char server_port[16] = "5000";
    struct Server_address_info **coap_servers= malloc(sizeof(struct Server_address_info*)*1);
    struct Server_address_info server;
    coap_servers[0]=&server;
    server.interface_addr=server_ip;
    server.port=server_port;
    server.uri=strdup("aaa");

    
    char client_ip[16] = "127.0.0.1";
    char client_port[16] = "3000";
    

    struct Address_info sender1;
    sender1.interface_addr=client_ip;
    sender1.port=client_port;
    struct Address_info **sender_list= malloc(sizeof(struct Address_info*)*1);
    sender_list[0]=&sender1;
    

    coap_client_init(sender_list,1,server);

    
    return 0;
}
