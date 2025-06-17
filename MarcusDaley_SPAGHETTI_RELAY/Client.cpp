#include "Client.h"



bool Client::isValidIPAddress(const char* address)
{
	//Simple validation for dotted format 
	int parts = 0;
	int currentPart = 0;
	bool hasDigit = false;
	for (int i = 0; address[i] != '\0'; i++) {
		char c = address[i];
		if (c >= '0' && c <= '9') {
			hasDigit = true;
			currentPart = currentPart * 10 + (c - '0');
			if (currentPart > 255) return false; // Each part must be <= 255
		}
		else if (c == '.') {
			if (!hasDigit || parts >= 3) return false; // Must have digits before dot and not more than 3 parts
			parts++;
			currentPart = 0;
			hasDigit = false;
		}
		else {
			return false; // Invalid character
		}
	}
	return hasDigit && parts == 3; // Must end with a digit and have exactly 4 parts
}
int Client::init(uint16_t port, char* address)
{
	std::cout << "[CLIENT] Connecting to " << address << ":" << port << std::endl;
	//Validate the IP address format
	if (!isValidIPAddress(address)) {
		std::cerr << "[CLIENT] Invalid IP address format: " << address << std::endl;
		return ADDRESS_ERROR;
	}
	//Create a socket
	clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(clientSocket == INVALID_SOCKET) {
		std::cerr << "[CLIENT] Socket creation failed: " << WSAGetLastError() << std::endl;
		return SETUP_ERROR;
	}
	//Set up the server address structure
	sockaddr_in serverAddress;
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(port);
	//Convert the IP address from string to binary format
	if(inet_addr(address) == INADDR_NONE) {
		std::cerr << "[CLIENT] Invalid IP address: " << address << std::endl;
		closesocket(clientSocket);
		return ADDRESS_ERROR;
	}
	serverAddress.sin_addr.s_addr = inet_addr(address);
	//Connect to the server
	if(connect(clientSocket, (sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
		int error = getError();
		std::cout << "[CLIENT] Connection failed: " << error << std::endl;
		closesocket(clientSocket);
		//Check if error is due to address or socket issues
		if (error == WSAEINTR || error == WSAECONNABORTED) {
			return SHUTDOWN;
		}
		return CONNECT_ERROR;
	}
	std::cout << "[CLIENT] Connected to " << address << ":" << port << std::endl;
	initialized = true;
	return SUCCESS;
}
int Client::readMessage(char* buffer, int32_t size)
{
	if (!initialized || clientSocket == INVALID_SOCKET)
	{
		return DISCONNECT;
	}
	//First,recieve the message Length (1 byte)
	uint8_t messageLength = 0;
	int result = recv(clientSocket, (char*)&messageLength, sizeof(messageLength), 0);
	if (result == 0)
	{
		std::cout << "[CLIENT] Client disconnected." << std::endl;
		return SHUTDOWN;
	}
	if (result == SOCKET_ERROR)
	{
		int error = getError();

		if (error == WSAECONNRESET|| error == WSAECONNABORTED)
		{
			std::cout << "[CLIENT] Error recieving message length: " << error << std::endl;
			return SHUTDOWN;
		}
		
		return DISCONNECT;
	}
	//Check  if message fits in buffer
	if (messageLength >= size)
	{
		std::cerr << "[CLIENT] Message length exceeds buffer size." << std::endl;
		return PARAMETER_ERROR;
	}
	//Recieve the actual message withpartial receive loop
	int totalReceived = 0;
	while (totalReceived < messageLength)
	{
		result = recv(clientSocket, buffer + totalReceived, messageLength - totalReceived, 0);
		if (result == 0) {
			std::cout << "[CLIENT] Server disconnected during message receive." << std::endl;

			return SHUTDOWN;

		}
		if (result == SOCKET_ERROR)
		{
			int error = getError();
			if (error == WSAECONNRESET || error == WSAECONNABORTED)
			{
				std::cout << "[ CLIENT] Client disconnected." << std::endl;
				return SHUTDOWN;
			}
			std::cerr << "[CLIENT] Error receiving message: " << error << std::endl;
			return DISCONNECT;
		}

		totalReceived += result;
	}
	//Null-terminate the buffer
	buffer[messageLength] = '\0';
	std::cout << "[CLIENT] Received message: \"" << buffer << "\"" << std::endl;
	return SUCCESS;
}
int Client::sendMessage(char* data, int32_t length)
{
	if (!initialized || clientSocket == INVALID_SOCKET)
	{
		return DISCONNECT;
	}
	//Validate message length
	if (length < 0 || length > 255)
	{
		std::cerr << "[CLIENT] Invalid message length: " << length << std::endl;
		return PARAMETER_ERROR;
	}
	std::cout << "[CLIENT] Sending message of length: \"" << data << "\"(length: " << length << ")" << std::endl;
	//Send message length first
	uint8_t messageLength = (uint8_t)length;
	int result = send(clientSocket, (char*)&messageLength, sizeof(messageLength), 0);
	if (result == 0)
	{
		std::cout << "[CLIENT] Client disconnected during lengh send." << std::endl;
		return SHUTDOWN;
	}
	if (result == SOCKET_ERROR)
	{
		int error = getError();
		std::cout << "[CLIENT] Error sending message length: " << error << std::endl;
		if (error == WSAEINTR || error == WSAECONNABORTED)
		{
			std::cout << "[CLIENT] Client disconnected during length send." << std::endl;
			return SHUTDOWN;
		}
		//std::cerr << "[CLIENT] Error sending message length: " << error << std::endl;
		return DISCONNECT;
	}
	//Send Message data using the helper function
	result = sendTcpData(clientSocket, data, length);
	if (result != length)
	{
		int error = getError();
		std::cerr << "[CLIENT] Error sending message data: " << error << std::endl;
		if (error == WSAEINTR || error == WSAECONNABORTED)
		{
			std::cout << "[CLIENT] Client disconnected during data send." << std::endl;
			return SHUTDOWN;
		}
		return DISCONNECT;
	}
	std::cout << "[CLIENT] Message sent successfully." << std::endl;
	return SUCCESS;
}
void Client::stop()
{
	std::cout << "[[CLIENT] Stopping server..." << std::endl;
	if (clientSocket != INVALID_SOCKET)
	{
		shutdown(clientSocket, SD_BOTH);
		close(clientSocket);
		clientSocket = INVALID_SOCKET;

	}
	initialized = false;
	std::cout << "[CLIENT] Client stopped." << std::endl;
}