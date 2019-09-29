#include "server_api.h"
#include <coap2/coap.h>
#include <stdio.h>


struct Servers server_storage;

static void message_handler(struct coap_context_t *ctx, struct coap_resource_t *res, struct coap_session_t *session,struct coap_pdu_t *received, struct coap_binary_t * bin, struct coap_string_t * str, struct coap_pdu_t * response){

    response->code = COAP_RESPONSE_CODE(205);

    coap_add_data(response, 6, (u_int8_t *)"world\0");
}

void coap_server_init(struct Server_address_info **server_details, int server_count){
    //Initialises all clients and sets server destination

    coap_startup(); //Start coap and create context
    coap_context_t  *ctx;
    ctx = coap_new_context(NULL);
    coap_endpoint_t **eps= malloc(sizeof(coap_endpoint_t*)*server_count); //create destinations
    server_storage.eps=eps;

    coap_resource_t **res =  malloc(sizeof(coap_resource_t*)*server_count); //create resources
    server_storage.res=res;


    printf("Creating endpoints\n");

    for(int i=0;i< server_count;i++){
        coap_address_t dst;
        //resolve this address

        

        resolve_address(server_details[i]->interface_addr, server_details[i]->port, &dst);
             
        coap_endpoint_t *ep;
        ep =  coap_new_endpoint(ctx, &dst, COAP_PROTO_UDP);
        eps[i] =ep;

        res[i] = coap_resource_init(coap_make_str_const(server_details[i]->uri), 0);

        coap_register_handler(res[i], COAP_REQUEST_GET,
                        message_handler);

        coap_add_resource(ctx, res[i]);
       
    }
    while (1==1) { coap_run_once(ctx, 0); }


    coap_free_context(ctx);
    coap_cleanup();
    printf("Done everything\n");

    return;
    


}
