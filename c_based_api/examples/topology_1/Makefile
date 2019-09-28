CC=gcc
LIBDIR= ../../
INCLUDES= -g
LIBLOCATION=/usr/local/lib/
LIBCOAP=$(LIBLOCATION)libcoap-2.so
LIBJSON=$(LIBLOCATION)libcjson.so

all: clients

clients: client.o
	$(CC) $(INCLUDES) -o client.out clients.c client_api.o $(LIBCOAP) $(LIBJSON)

client.o: 
	$(CC) -c $(LIBDIR)client_api/client_api.c 

clean: 
	rm -f *.o *.out;

    
