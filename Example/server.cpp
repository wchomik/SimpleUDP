#include <iostream>
#include "../SimpleUDP.h"

bool add(SimpleUDP &server, int buffer_len, char * buffer)
{
    int a;
    int b;
    message::retrive(buffer_len, buffer, a, b);
    server.send(100, a + b);
    return true;
}

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
    try {
        server.set_log_stream(std::cout);
        server.register_message_handler(100, std::bind(add, server, std::placeholders::_1, std::placeholders::_2));

        server.listen();
        server.run();
    } catch(const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }
}