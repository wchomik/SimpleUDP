CC=g++
CC_FLAGS = -g -std=c++14 -Wall
LD_FLAGS =

EXEC=debug-client
SOURCES=$(wildcard *.cpp)
OBJECTS=$(SOURCES:.cpp=.o)

all: server client

client:client.cpp ../SimpleUDP.h
	$(CC) $(CC_FLAGS) $< -o $@

server:server.cpp ../SimpleUDP.h
	$(CC) $(CC_FLAGS) $< -o $@

.PHONY: clean

clean:
	rm client server
