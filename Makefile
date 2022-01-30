all: 
	gcc -o vpnclient client.c -lssl -lcrypto 
	gcc -o vpnserver server.c -lssl -lcrypto  -lcrypt -lpthread

clean: 
	rm -f vpnclient vpnserver 
	rm -f *~

