#include <iostream>
#include "../SimpleUDP.h"

void work(SimpleUDP * conn, bool conected){
	int a;
	int b;

	std::cout << "Enter two numbers:\n";
	if(std::cin >> a >> b) {
		std::cout << "Add sending: " << a << " + " << b << "\n";
		conn->send(100, a, b);
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
		SimpleUDP conn(port);
		conn.set_log_stream(std::cout);
		conn.set_work(std::bind(work, &conn, std::placeholders::_1));
		conn.register_message_handler(100, print_result);
		
		conn.connect(argv[1], port);
		conn.run(false);
	} catch(const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }
}
