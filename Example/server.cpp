#include <iostream>
#include "../SimpleUDP.h"

int main(int argc, char **argv) {
	int port;
	if(argc!=2){
		std::cout << "USAGE: server [server_port]\n";
		exit(1);
	}else{
		sscanf (argv[1],"%d",&port);
		if(port < 0 && port > 49152){
			std::cout << "Wrong port number!\n";
			exit(1);
		}
		std::cout << "Port: " << port << "\n";
	}

    SimpleUDP server(port);
    server.set_log_stream(std::cout);
    server.start();
    server.run();
}