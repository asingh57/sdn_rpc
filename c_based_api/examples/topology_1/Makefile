CC=gcc
LIBDIR= ../../
INCLUDES= -g
LIBLOCATION=/usr/local/lib/
LIBCOAP=$(LIBLOCATION)libcoap-2-openssl.so
LIBJSON=$(LIBLOCATION)libcjson.so

all: clients servers

clients: client.o server.o
	$(CC) $(INCLUDES) -o client.out create_client.c client_api.o common.o $(LIBCOAP) $(LIBJSON)

servers: server.o
	$(CC) $(INCLUDES) -o server.out create_server.c server_api.o common.o $(LIBCOAP) $(LIBJSON)

server.o: common.o
	$(CC) $(INCLUDES) -c $(LIBDIR)server_api/server_api.c

client.o: common.o
	$(CC) $(INCLUDES) -c $(LIBDIR)client_api/client_api.c

common.o:
	$(CC) $(INCLUDES) -c $(LIBDIR)common/common.c

clean: 
	rm -f *.o *.out;

    
