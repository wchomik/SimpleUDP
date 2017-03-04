#include <iostream>
#include "../SimpleUDP.h"

int main(int argc, char **argv) {
	int port;
	if(argc!=3){
		std::cout << "USAGE: client [server_ip] [server_port]\n";
		exit(1);
	}else{
		sscanf (argv[2],"%d",&port);
		if(port < 0 && port > 49152){
			std::cout << "Wrong port number!\n";
			exit(1);
		}
		std::cout << "Server: " << argv[1] << "\n";
		std::cout << "Port: " << port << "\n";
	}

    SimpleUDP client(port);
	client.start();
}