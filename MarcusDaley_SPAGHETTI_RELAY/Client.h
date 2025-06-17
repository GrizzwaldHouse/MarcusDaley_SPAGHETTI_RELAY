#pragma once

#define _WINSOCK_DEPRECATED_NO_WARNINGS

  
#include "platform.h"
#include "CommandMessages.h"

#include <iostream>
#include <cstring>
class Client
{
private:
	SOCKET clientSocket;
	bool initialized;
	bool isValidIPAddress(const char* address);
	public:
		Client() : clientSocket(INVALID_SOCKET), initialized(false) {}
	int init(uint16_t port, char* address);
	int readMessage(char* buffer, int32_t size);
	int sendMessage(char* data, int32_t length);
	void stop();
};