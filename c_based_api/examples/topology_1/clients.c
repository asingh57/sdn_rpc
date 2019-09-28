#include <cjson/cJSON.h>
#include "../../client_api/client_api.h"

int main(){
    

    
    char ip[16] = "127.0.0.1";
    char port[16] = "3000";
    char ip2[16] = "127.0.0.1";
    char port2[16] = "5000";

    struct Address_info sender1;
    sender1.interface_addr=ip;
    sender1.port=port;
    struct Address_info **sender_list= malloc(sizeof(struct Address_info*)*1);
    sender_list[0]=&sender1;
    struct Address_info server;
    server.interface_addr=ip2;
    server.port=port2;

    coap_init(sender_list,1,server);
    return 0;
}
