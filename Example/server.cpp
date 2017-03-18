#include <iostream>
#include "../SimpleUDP.h"

bool add(SimpleUDP * conn, int buffer_len, char * buffer)
{
    int a;
    int b;
    message::retrive(buffer_len, buffer, a, b);
    std::cout << "Add: " << a << " + " << b << "\n";
    conn->send(100, a + b);
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

    try {
        SimpleUDP conn(port);
        conn.set_log_stream(std::cout);
        conn.register_message_handler(100, std::bind(add, &conn, std::placeholders::_1, std::placeholders::_2));

        conn.listen();
        conn.run();
    } catch(const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }
}
