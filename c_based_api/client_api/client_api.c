#include "client_api.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>

struct Sessions session_storage;

static void message_handler(struct coap_context_t *ctx, coap_session_t *session, coap_pdu_t *sent, coap_pdu_t *received, const coap_tid_t id)
{
    unsigned char* data = NULL;
    size_t data_len;
    if(received->data == NULL) {
        printf("No data\n");
        printf("%d\n",received->code);
    }
    else{
        printf("Data Received: %s\n Receive code: %d\n",received->data,received->code);
    }
}

void coap_client_init(struct Address_info **client_details, int client_count,struct Server_address_info dest_info){
    //Initialises all clients and sets server destination

    coap_startup(); //Start coap and create context
    coap_context_t  *ctx;
    ctx = coap_new_context(NULL);
    coap_address_t dst; //destination coap address
    coap_session_t ** sessions= malloc(sizeof(coap_session_t*)*client_count); //create pointers for sessions
    session_storage.sessions=sessions;
    printf("Creating sessions\n");
    for(int i=0;i< client_count;i++){
        coap_address_t src;
        /*int sockfd;
        if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
            perror("socket creation failed"); 
            exit(EXIT_FAILURE); 
        } 
        printf("Socket success\n");
        int enable = 1;
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
            error("setsockopt(SO_REUSEADDR) failed");

        
        //first open a temporary udp port so resolve address doesnt fail
        struct sockaddr_in servaddr;
        memset(&servaddr, 0, sizeof(servaddr)); 
        servaddr.sin_family    = AF_INET; // IPv4         
        struct in_addr in;
        inet_aton(client_details[i]->interface_addr, &in);
        servaddr.sin_port = htons(atoi(client_details[i]->port)); 
        servaddr.sin_addr.s_addr = in.s_addr;
        if ( bind(sockfd, (const struct sockaddr *)&servaddr,  
            sizeof(servaddr)) < 0 ) 
        { 
            perror("bind failed"); 
            exit(EXIT_FAILURE); 
        }
        else{
            printf("bind success\n");
        }*/
        //resolve this address
        resolve_address(client_details[i]->interface_addr, client_details[i]->port, &src);
             
        //close this udp port
        /*
        close(sockfd);
        */
        resolve_address(dest_info.interface_addr, dest_info.port, &dst); 
        coap_session_t *session;
        session = coap_new_client_session(ctx, &src, &dst,
                                                  COAP_PROTO_UDP);
        sessions[i] =session;

        coap_register_response_handler(ctx, message_handler);
        coap_pdu_t *pdu=NULL;
        pdu = coap_pdu_init(COAP_MESSAGE_CON,
                          COAP_REQUEST_GET,
                          0,
                          coap_session_max_pdu_size(session));
        if (!pdu) {
          coap_log( LOG_EMERG, "cannot create PDU\n" );
        }

        coap_uri_t *uri;


        coap_add_option(pdu, COAP_OPTION_URI_PATH, strlen(dest_info.uri), dest_info.uri);

        

        printf("URI CREATED\n");
        /* and send the PDU */
        coap_send(session, pdu);
        printf("pdu sent\n");
        coap_run_once(ctx, 0);
        printf("session run\n");
        coap_session_release(session);
        coap_free_context(ctx);
        coap_cleanup();
    }
    printf("Done everything\n");
    
}


