#ifndef SIMPLE_UDP_H
#define SIMPLE_UDP_H

#include <arpa/inet.h>
#include <linux/wireless.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <memory.h>
#include <unistd.h>
#include <system_error>
#include <stdexcept>
#include <vector>
#include <stack>
#include <functional>
#include <sys/ioctl.h>
#include <chrono>
#include <thread>
#include <ctime>

#define MICROINSECOND 1000000
#define MESSAGE_BUF_SIZE 65536 //Max possible packet size

/*Messages from 0-99 are reserved*/
#define MSG_IN_HELLO              1
#define MSG_IN_KEEP_ALIVE         2
#define MSG_IN_ECHO               3
#define MSG_IN_GOODBYE            99

/*Messages from 0-99 are reserved*/
#define MSG_OUT_SEND_WIFI_QUALITY 1

#define ILOG(str) \
if (is_log_set) {\
*log_stream << "I " << [](){auto tt = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()); return std::ctime(&tt);} << ": " << str << std::endl;\
}

#define ELOG(str) \
if (is_log_set) {\
*err_stream << "E " << [](){auto tt = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()); return std::ctime(&tt);} << ": " << str << std::endl;\
}

#define ERNOLOG(str) \
if (is_log_set) {\
*err_stream << "E " << [](){auto tt = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()); return std::ctime(&tt);} << ": " << str << " (" << strerror(errno) << ")" << std::endl;\
}

class message
{
private:
    char buf[MESSAGE_BUF_SIZE];
    int ptr;


    template<typename T>
    void build_message(T obj) {
        int size = sizeof(T);
        if(ptr + size > MESSAGE_BUF_SIZE) {
            //ELOG("Message buffer too small");
            throw std::system_error(ENOBUFS, std::system_category());
        }
        memcpy(buf+ptr, &obj, size);
        ptr += size;
    }

    template<typename First, typename... Rest>
    void build_message(First first, Rest... rest) {
        build_message(first);
        build_message(rest...);
    }

public:

    template<typename... Args>
    message(Args... args): buf{0}, ptr(0)
    {
        build_message(args...);
    }

    int get(int buffer_len, char * out_buff) {
        memset(out_buff, 0, buffer_len);

        if(ptr > buffer_len) {
            //ELOG("Send buffer too small");
            throw std::system_error(ENOBUFS, std::system_category());
        }
        memcpy(out_buff, buf, ptr);
        return ptr;
    }

    template<typename First, typename... Rest>
    static void retrive(int buffer_len, char * in_buffer, First& first, Rest&... rest)
    {
        if(buffer_len < 0) {
            //ELOG("Buffer is not long enough for given parameters");
            return;
        }
        retrive(buffer_len, in_buffer, first);
        retrive(buffer_len - sizeof(First), in_buffer + sizeof(First), rest...);
    }

    template<typename T>
    static void retrive(int buffer_len, char * in_buffer, T &obj)
    {
        if(buffer_len < 0) {
            //ELOG("Buffer is not long enough for given parameters");
            return;
        }
        obj = *(T*)in_buffer;
    }
};

class SimpleUDP
{
private:
    const int buffer_size = MESSAGE_BUF_SIZE;
    const int time_out = 5000000;

    bool connected = false;
    int  port      = 0;
    bool is_wifi   = false;

    int server_sockfd;
    int client_sockfd;

    socklen_t size;

    struct sockaddr_in server_address;
    struct sockaddr_in client_address;

    struct iwreq iwr;
    struct ifreq ifr;
    struct iw_statistics iwstats;

    char * in_buffer;
    char * out_buffer;

    bool is_log_set = false;
    std::ostream *log_stream;

    bool is_err_set = false;
    std::ostream *err_stream;

    bool halt = false;

    std::string instance_name = "MessageHandler";
    std::stack<message> out_messages;
    std::vector<std::function<bool(int, char *)>> message_handlers;
    std::function<void(bool)> work;

    void check_wifi_quality(bool log, int &level, int &noise, int &qual)
    {
        if( ioctl( server_sockfd, SIOCGIFFLAGS, &ifr ) != -1 )
        {
            if((ifr.ifr_flags & ( IFF_UP | IFF_RUNNING )) == ( IFF_UP | IFF_RUNNING )) {
                is_wifi = true;
                if(log) {
                    ILOG("WiFi is up and running.");
                }

                if(ioctl(server_sockfd, SIOCGIWSTATS, &iwr) != -1) {
                    if(log) {
                        ILOG("WiFi quality:" << std::endl
                            << "level:   " << (int)(((iw_statistics *)iwr.u.data.pointer)->qual.level) << std::endl
                            << "noise:   " << (int)(((iw_statistics *)iwr.u.data.pointer)->qual.noise) << std::endl
                            << "qual:    " << (int)(((iw_statistics *)iwr.u.data.pointer)->qual.qual));
                    } else {
                        level = (int)(((iw_statistics *)iwr.u.data.pointer)->qual.level);
                        noise = (int)(((iw_statistics *)iwr.u.data.pointer)->qual.noise);
                        qual  = (int)(((iw_statistics *)iwr.u.data.pointer)->qual.qual);
                    }
                } else {
                    ERNOLOG("ioctl error");
                    throw std::system_error(errno, std::system_category());
                }
            } else {
                if(!log) {
                    ELOG("WiFi is NOT up and running. Stopping sending and receiving messages");
                    connected = false;
                }
            }
        }
        else
        {
            is_wifi = false;
            if(log) {
                ILOG("Connection is not Wireless. Skipping quality checks.");
            }
            //ERNOLOG("ioctl error");
            //throw std::system_error(errno, std::system_category());
        }
    }

    void stop()
    {
        ILOG ("Closing socket");
        close(server_sockfd);
    }

    int process_output_message(int buffer_len, char * buffer)
    {
        if(out_messages.empty()) {
            return 0;
        } else {
            int message_len = out_messages.top().get(buffer_len, buffer);
            out_messages.pop();
            return message_len;
        }
    }

    unsigned char process_input_message(int buffer_len, char * buffer)
    {
        if(buffer_len >= 1) {
            unsigned char message_id = buffer[0];
#ifdef DEBUG
            ILOG("Message received "<< (int)message_id);
#endif
            if(connected || (message_id == MSG_IN_HELLO)) {
                if ((message_handlers[message_id])(buffer_len - 1, buffer + 1)) {
                    return message_id;
                } else {
                    return 0;
                }
            } else {
                return 0;
            }
        } else {
            ELOG("Message lenght less than 1");
            throw std::system_error(EINVAL, std::system_category());
        }
    }

    bool message_not_implemented(int buffer_len, char * buffer)
    {
        ELOG("Message not implemented");
        return false;
    }

    bool message_keep_alive(int buffer_len, char * buffer) {return true;}

    bool message_echo(int buffer_len, char * buffer)
    {
        ILOG("Echo message received: " << buffer);
        this->process_output_message(buffer_len, buffer);
        return true;
    }

    bool message_hello(int buffer_len, char * buffer)
    {
        if(instance_name == std::string(buffer)) {
            ILOG("Succesfully connected");
            this->process_output_message(buffer_len, buffer);
            return true;
        } else {
            ELOG("Connection declined. Token given: (" << buffer << ")");
            return false;
        }
    }

    bool message_goodbye(int buffer_len, char * buffer)
    {
        ILOG("Succesfully disconnected");
        return true;
    }

public:
    SimpleUDP(int in_port)
    {
        port = in_port;

        in_buffer  = (char *)malloc(buffer_size+1);
        out_buffer = (char *)malloc(buffer_size+1);

        memset(&iwr, 0, sizeof(iwr) );
        strcpy(iwr.ifr_name, "wlan0");

        memset(&ifr, 0, sizeof(ifr) );
        strcpy(ifr.ifr_name, "wlan0" );

        iwr.u.data.pointer = &iwstats;
        iwr.u.data.length = sizeof(struct iw_statistics);
        iwr.u.data.flags = 1;

        for(int i = 0; i < 256; i++)
            message_handlers.push_back(std::bind(&SimpleUDP::message_not_implemented, this, std::placeholders::_1, std::placeholders::_2));

        message_handlers[MSG_IN_KEEP_ALIVE] = std::bind(&SimpleUDP::message_keep_alive, this, std::placeholders::_1, std::placeholders::_2);
        message_handlers[MSG_IN_HELLO]      = std::bind(&SimpleUDP::message_hello, this, std::placeholders::_1, std::placeholders::_2);
        message_handlers[MSG_IN_ECHO]       = std::bind(&SimpleUDP::message_echo, this, std::placeholders::_1, std::placeholders::_2);
        message_handlers[MSG_IN_GOODBYE]    = std::bind(&SimpleUDP::message_goodbye, this, std::placeholders::_1, std::placeholders::_2);

    }

    ~SimpleUDP()
    {
        stop();
        free(in_buffer);
        free(out_buffer);
    }

    void set_log_stream(std::ostream& ost) {
        log_stream = &ost;
        is_log_set = true;
        if(!is_err_set) {
            set_err_stream(ost);
        }
    }

    void set_err_stream(std::ostream& ost) {
        err_stream = &ost;
        is_err_set = true;
    }

    void listen()
    {
        ILOG("Setting new sockets on port: " << port);

        size = sizeof (struct sockaddr);

        server_sockfd = socket (PF_INET, SOCK_DGRAM, 0);
        client_sockfd = socket (PF_INET, SOCK_DGRAM, 0);

        memset (&server_address, 0, sizeof (server_address));
        memset (&client_address, 0, sizeof (client_address));
        client_address.sin_family = PF_INET;
        server_address.sin_family = PF_INET;
        server_address.sin_port   = htons (port);
        server_address.sin_addr.s_addr = htonl (INADDR_ANY);

        if (bind (server_sockfd, (struct sockaddr *) &server_address, sizeof (struct sockaddr_in))) {
            ERNOLOG ("Bind");
            throw std::system_error(errno, std::system_category());
        }

        int level;
        int noise;
        int qual;
        check_wifi_quality(true, level, noise, qual);
    }

    void connect(std::string address, int port)
    {
        ILOG("Setting new sockets on port: " << port);

        size = sizeof (struct sockaddr);

        server_sockfd = socket (PF_INET, SOCK_DGRAM, 0);
        client_sockfd = socket (PF_INET, SOCK_DGRAM, 0);

        memset (&server_address, 0, sizeof (server_address));
        memset (&client_address, 0, sizeof (client_address));
        client_address.sin_family = PF_INET;
        client_address.sin_port   = htons (port);
        client_address.sin_addr.s_addr = inet_addr(address.c_str());
        server_address.sin_family = PF_INET;

        ILOG("Connecting to server");
        //int out_buffer_len = message((unsigned char)MSG_IN_HELLO, instance_name.c_str()).get(buffer_size, out_buffer);
        out_buffer[0] = (unsigned char)MSG_IN_HELLO;
        memcpy(out_buffer + 1, instance_name.c_str(), instance_name.length());
        int out_buffer_len = instance_name.length() + 1;
        sendto(server_sockfd, out_buffer, out_buffer_len, 0, (struct sockaddr *) &client_address, sizeof (struct sockaddr));

        ILOG("Waiting for response");
        recvfrom(server_sockfd, in_buffer, buffer_size, 0, (struct sockaddr *) &server_address, &size);

        ILOG("Server responded");
        ::connect(server_sockfd, (struct sockaddr *) &server_address, size);

        int level;
        int noise;
        int qual;
        check_wifi_quality(true, level, noise, qual);
    }

    void set_work(std::function<void(bool)> function) {
        work = function;
    }

    void register_message_handler(int message_id, const std::function<bool(int, char *)> & function) {
        if(message_id < 100 || message_id > 255) {
            throw std::range_error("Message beyond 100-255 range");
        }
        message_handlers[message_id] = function;
    }

    template<typename... Args>
    void send(const char message_id, Args... args)
    {
        out_messages.push(message(message_id, args...));
    }

    void run() {
        run(0);
    }

    void run(int frequency)
    {
        ILOG("Server started");

        auto loop_duration = frequency ? std::chrono::microseconds(1000000 / frequency) : std::chrono::microseconds(0);
        int wait_flag = frequency ? MSG_DONTWAIT : 0;
        
        //int last_in_message = 0;

        auto start_time = std::chrono::high_resolution_clock::now();
        auto end_time   = std::chrono::high_resolution_clock::now();
        while (true) {
            start_time = std::chrono::high_resolution_clock::now();
            if(connected) {
                //last_in_message += MICROINSECOND / frequency;
                int in_message_len = -1;

                while((in_message_len = recv(client_sockfd, in_buffer, buffer_size, wait_flag)) != -1) {      
                    unsigned char message_id = process_input_message(in_message_len, in_buffer);
                    memset(in_buffer, 0, buffer_size);
                    //last_in_message = 0;
                    if (message_id == MSG_IN_GOODBYE) {
                        connected = false;
                    }
                }

                /*if(last_in_message > time_out) {
                    ILOG("No incoming communication since " << last_in_message / MICROINSECOND << "s. Restarting server");
                    stop();
                    //start();
                    connected = false;
                }*/
            }

            if(work) {
                work(connected);
            }

            if(connected){
                int out_message_len;

                if(is_wifi) {
                    int level;
                    int noise;
                    int qual;

                    check_wifi_quality(false, level, noise, qual);
                    out_message_len = message((unsigned char)MSG_OUT_SEND_WIFI_QUALITY, level, noise, qual).get(buffer_size, out_buffer);
                    send(client_sockfd, out_buffer, out_message_len, 0);
                }

                try {
                    while((out_message_len = process_output_message(buffer_size, out_buffer))) {
                        send(client_sockfd, out_buffer, out_message_len, 0);
                    }
                } catch (std::system_error& error) {
                    ELOG("Communication error (" << error.code() << "): " << error.what());
                }

            } else{
                if(!frequency){
                    ILOG("Waiting for incoming connections.\n");
                }
                size = sizeof(client_address);

                ssize_t num_bytes = recvfrom (server_sockfd, in_buffer, buffer_size, wait_flag, (struct sockaddr *) &client_address, &size);

                if (0 < num_bytes && process_input_message(num_bytes, in_buffer)) {
                    if(::connect (client_sockfd, (struct sockaddr *) &client_address, size)) {
                        ERNOLOG("Cannot connect");
                    }
                    ILOG("Connected to "<< inet_ntoa(client_address.sin_addr) << ":" << ntohs (client_address.sin_port));
                    memcpy(in_buffer, "Hello", strlen("Hello") + 1);
                    if (write (client_sockfd, in_buffer, strlen("Hello") + 1) < 0) ERNOLOG ("Cannot write to socket");
                    connected       = true;
                    //last_in_message = 0;
                } else if(num_bytes == -1) {
                    if(errno != EAGAIN && errno != EWOULDBLOCK) ERNOLOG("Cannot accept incoming connections");
                }
            }

            end_time   = std::chrono::high_resolution_clock::now();

            auto time_difference = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
            auto time_to_sleep = loop_duration - time_difference;
            if(time_to_sleep.count() > 0) {
                std::this_thread::sleep_for(time_to_sleep);
            } else {
                ELOG("Main procedures take too long!!!");
            }

            if(halt) {
                ILOG("Halting main loop");
                return;
            }
        }
    }
};

#undef MICROINSECOND
#undef MESSAGE_BUF_SIZE
#undef MSG_IN_HELLO
#undef MSG_IN_KEEP_ALIVE
#undef MSG_IN_ECHO
#undef MSG_IN_GOODBYE
#undef MSG_OUT_SEND_WIFI_QUALITY
#undef ILOG
#undef ELOG
#undef ERNOLOG

#endif
