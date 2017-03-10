#include <iostream>
#include "../SimpleUDP.h"

void work(SimpleUDP * client, bool conected){
	int a;
	int b;

	std::cout << "Enter two numbers:\n";
	if(std::cin >> a >> b) {
		std::cout << "Add sending: " << a << " + " << b << "\n";
		client->send(100, a, b);
	}
}

bool print_result(int buffer_len, char * buffer)
{
    int c;
    message::retrive(buffer_len, buffer, c);
    std::cout << "Add result: " << c << "\n";
    return true;
}

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

	try {
		SimpleUDP client(port);
		client.set_log_stream(std::cout);
		client.set_work(std::bind(work, &client, std::placeholders::_1));
		client.register_message_handler(100, print_result);
		
		client.connect(argv[1], port);
		client.run(false);
	} catch(const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }
}
