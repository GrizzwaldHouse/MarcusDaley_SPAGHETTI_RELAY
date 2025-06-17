#include "Server.h"
#include <cstring>
#define _WINSOCK_DEPRECATED_NO_WARNINGS
Server::Server() : listenSocket(INVALID_SOCKET),  serverRunning(false), serverPort(DEFAULT_PORT), maxClients(DEFAULT_CAPACITY),commandChar(DEFAULT_COMMAND_CHAR)
{
	std::cout << "[SERVER] Server instance created." << std::endl;
}

Server::~Server()
{
	//ShutDown();

}

//Server() : listenSocket(INVALID_SOCKET), clientSocket(INVALID_SOCKET), isConnected(false) {};


int Server::InitializeServer()
{
	int result = SUCCESS;
	LogMessage("Initializing TCP server on port " + std::to_string(serverPort));
	//Create listening socket
	listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listenSocket == INVALID_SOCKET) {
		LogMessage("Failed to create socket - " + std::to_string(getError()));
		result = SETUP_ERROR;
	}
	else
	{
		//Set SO_REUSEADDR option to allow reuse of the address
		int opt = 1;
		if(setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
			LogMessage("Failed to set socket options - " + std::to_string(getError()));
			
		}
		//Setup server address structure
		sockaddr_in serverAddress = {};
		serverAddress.sin_family = AF_INET; // IPv4
		serverAddress.sin_addr.s_addr = INADDR_ANY; // Listen on all interfaces
		serverAddress.sin_port = htons(serverPort); // Convert port to network byte order

		//Bind socket to address
		if (bind(listenSocket, (sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
			int error = getError();
			LogMessage("Failed to bind socket to port" + std::to_string(serverPort) + " - Error: " + std::to_string(error));
			close(listenSocket);
			listenSocket = INVALID_SOCKET;
			result = BIND_ERROR;
		}
		else if (listen(listenSocket,SOMAXCONN)==SOCKET_ERROR)
		{
			int error = getError();
			LogMessage("Failed to bind socket - Error: " + std::to_string(serverPort));
			close(listenSocket);
			listenSocket = INVALID_SOCKET;
			result = SETUP_ERROR;
		}
		else
		{
			//Initialize fd_sets for select()
			FD_ZERO(&masterSet);
			FD_SET(listenSocket, &masterSet);
			LogMessage("TCP server intialized successfully on port " + std::to_string(serverPort));

		}
	}
	return result;
}

int Server::PromptServerConfiguration()
{
	std::cout << "Configure your server settings: " << std::endl;
	//Get Port number
	std::cout << "\nEnter TCP port number (default " << DEFAULT_PORT << "): ";
	std::string portInput;
	std::getline(std::cin, portInput);
	if (!portInput.empty()) {
		try {
			serverPort = std::stoi(portInput);
			if (serverPort < 1024 || serverPort > 65535) {
				std::cout << "Invalid port number. Using default port " << DEFAULT_PORT << "." << std::endl;
				serverPort = DEFAULT_PORT;
			}
			else
			{
				serverPort = static_cast<uint16_t>(serverPort);
			}
		}
		catch (const std::exception&) {
			std::cout << "Invalid input. Using default port " << DEFAULT_PORT << "." << std::endl;
			serverPort = DEFAULT_PORT;
		}
	}
	//Get chat capacity
	std::cout << "Enter maximum number of clients (default " << DEFAULT_CAPACITY << "): ";
	std::getline(std::cin, portInput);
	if (!portInput.empty())
	{
		try
		{
			int capacity = std::stoi(portInput);
			if (capacity < 1 || capacity > 100) {
				std::cout << "Invalid capacity. Using default capacity " << DEFAULT_CAPACITY << "." << std::endl;
				maxClients = DEFAULT_CAPACITY;
			}
			else
			{
				maxClients = capacity;
			}
		}
			catch (const std::exception& e) {
				std::cout << "Invalid input. Using default capacity " << DEFAULT_CAPACITY << "." << std::endl;
				maxClients = DEFAULT_CAPACITY;
			}
		}
	//Get command character
	std::cout << "Enter command character (default '" << DEFAULT_COMMAND_CHAR << "'): ";
	std::getline(std::cin, portInput);
	if (!portInput.empty() && portInput.length()==1)
	{
		commandChar = portInput[0];
	}
#if DEBUG_MODE
	LogMessage("Server configuration: Port = " + std::to_string(serverPort) +
		", Max Clients = " + std::to_string(maxClients) +
		", Command Character = '" + commandChar + "'");
#endif
	return SUCCESS;
}

void Server::DisplayServerInfo()
{
	std::cout << "\n==== Server Information ===" << std::endl;
	std::cout << "Server Status : ACTIVE" << std::endl;
	std::cout << "Listening on port: " << serverPort << std::endl;
	std::cout << "Maximum clients allowed: " << maxClients << std::endl;
	std::cout << "Command character: '" << commandChar << "'" << std::endl;
	//Grt and display server IP address
	std::string ipAddress = GetServerIPAddress();
	if (!ipAddress.empty())
	{
		std::cout << "Server IP Address: " << ipAddress << std::endl;
		std::cout << " Full address: " << ipAddress << ":" << serverPort << std::endl;

	}
	else
	{
		std::cout << "Failed to retrieve server IP address." << std::endl;
	}
	//Show localhost option for local connections
	std::cout << "Localhost option: " << serverPort << std::endl;
	std::cout << "Sever ready for connections..." << std::endl;
	std::cout << "============================" << std::endl;
}

int Server::RunServer()
{
	serverRunning = true;
	LogMessage("Starting server main loop with select multiplexing");
	while (serverRunning)
	{//Copy master set to working set 
		readySet = masterSet;
		//Set timeout for select() 
		timeval timeout = { 1, 0 }; // 1 second timeout
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		//Wait for activity on any socket
		int activity = select(0, &readySet, nullptr, nullptr, &timeout);
		if (activity == SOCKET_ERROR)
		{
			int error = getError();
			LogMessage("Error: select() failed - Error: " + std::to_string(error));
			return SETUP_ERROR;
		}
		if(activity == 0)
		{
			//No activity, continue loop
			continue;
		}
		//Check if listening socket has incoming connection
		if (FD_ISSET(listenSocket, &readySet)) {
			int result = HandleNewConnection();
			if(result != SUCCESS) {
				LogMessage("Failed to handle new connection - Error: " + std::to_string(result));
			}
		}
		//Check all client sockets for incoming data
		std::vector<SOCKET> socketsToRemove;
		for (SOCKET clientSocket:clientSockets)
		{
			if(FD_ISSET(clientSocket, &readySet)) {
				int result = HandleClientMessage(clientSocket);
				if (result == DISCONNECT|| result==SHUTDOWN) {
					LogMessage("Error handling client data - Error: " + std::to_string(getError()));
					socketsToRemove.push_back(clientSocket);
				}
			}
		}
		//Remove disconnected sockets
		for (SOCKET socket : socketsToRemove) 
		{
			RemoveClient(socket);
			LogMessage("Client disconnected - Socket removed from set");
			
		}
	}
	LogMessage("Server main loop terminated.");
	return SUCCESS;
}

void Server::Shutdown()
{
	LogMessage("Shutting down server...");
	serverRunning = false;
	//Close all client sockets
	for (SOCKET clientSocket : clientSockets) {
		close(clientSocket);
		LogMessage("Closed client socket - Socket: " + std::to_string(clientSocket));
	}
	clientSockets.clear();
	//Close listening socket
	if (listenSocket != INVALID_SOCKET) {
		close(listenSocket);
		LogMessage("Closed listening socket - Socket: " + std::to_string(listenSocket));
		listenSocket = INVALID_SOCKET;
	}
	//Clear all data structures
	registeredClients.clear();
	activeClients.clear();
	FD_ZERO(&masterSet);
	FD_ZERO(&readySet);
	LogMessage("Server shutdown complete.");
}

int Server::HandleNewConnection()
{
	int result = SUCCESS;
	sockaddr_in clientAddress;
	int addrssLength = sizeof(clientAddress);

	//Accept new connection
	SOCKET newClientSocket = accept(listenSocket,(sockaddr*)&clientAddress,&addrssLength);
	if (newClientSocket == INVALID_SOCKET)
	{
		int error =getError();
		LogMessage("Failed to accept new connection - Error: " + std::to_string(error));
		result = CONNECT_ERROR;
	}
	else if (clientSockets.size()>= static_cast<size_t>(maxClients))
	{
		LogMessage("WARNING: Server at capacity. Please try again later.");
		close(newClientSocket);
		result = PARAMETER_ERROR;
	}
	else
	{
		//Add new client to tracking structures
		clientSockets.push_back(newClientSocket);
		FD_SET(newClientSocket, &masterSet);
		//Get client IP address for logging 
		char clientIP[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &clientAddress.sin_addr, clientIP, INET_ADDRSTRLEN);
		LogMessage("New client connected - IP: " + std::string(clientIP) + ",- Socket: " + std::to_string(newClientSocket));
		//Send welcome message to new client
		int welcomeResult = SendWelcomeMessage(newClientSocket);
		if (welcomeResult != SUCCESS)
		{
			LogMessage("Failed to send welcome message - Error: " + std::to_string(welcomeResult));
		}
	}
	return result;
}

int Server::HandleClientMessage(SOCKET clientSocket)
{
	int result = SUCCESS;
	char buffer[BUFFER_SIZE];
	//Receive framed message from client 
	int receivedResult = RecieveFramedMessage(clientSocket, buffer, BUFFER_SIZE);
	if (receivedResult != SUCCESS)
	{
		if(receivedResult==SHUTDOWN|| receivedResult==DISCONNECT) {
			LogMessage("Client disconnected - Socket: " + std::to_string(clientSocket));
			
		}
		else
		{
			LogMessage("Failed to receive message from client - Error: " + std::to_string(receivedResult));
			
		}
		result = receivedResult;
	}
	else 
	{
		std::string clientMessage(buffer);
		//Check if message is a command
		if (!clientMessage.empty() && clientMessage[0] == commandChar) {
			result = ProcessCommand(clientSocket, clientMessage);
		}
		else 
		{
			//Handle regular chat message 
			LogMessage("Chat message from client - Socket: " + std::to_string(clientSocket) + ", Message: " + clientMessage);
			std::string senderName = "Anonymous"; // Default sender name
			//Check if client is logged in and has a username
			if (activeClients.find(clientSocket) != activeClients.end()) {
				senderName = activeClients[clientSocket]; // Get username from active clients map
			}
			////If no user name is found deny and request login username
			//else if (registeredClients.find(senderName) == registeredClients.end()) {
			//	std::string errorMessage = "ERROR: You must register and login to send messages. Type '" + std::string(1, commandChar) + "help' for instructions.";
			//	result = SendFramedMessage(clientSocket, errorMessage);
			//	LogMessage("Client not registered - Requesting registration or login - Socket: " + std::to_string(clientSocket));
			//}
			else
			{
				//Broadcast message to all clients except the sender
				std::string broadcastMessage = senderName + ": " + clientMessage;
				result = BroadcastToAllClients(broadcastMessage, clientSocket);
			}
			
			result = SUCCESS;
		}
	}
	return result;
}

std::string Server::CreateMaskedPassword(const std::string& password)
{
	if (password.length() <= 2) {
		// For very short passwords, just return all X's
		return std::string(password.length(), 'X');
	}
	else if (password.length() <= 4) {
		// For short passwords, show first character and mask the rest
		return password.substr(0, 1) + std::string(password.length() - 1, 'X');
	}
	else {
		// For longer passwords, show first and last character with X's in between
		return password.substr(0, 1) + std::string(password.length() - 2, 'X') + password.substr(password.length() - 1, 1);
	}
}

int Server::BroadcastToAllClients(const std::string& message , SOCKET excludeSocket)
{
	int successCount = 0;
	int failureCount = 0;

	// Iterate through all connected client sockets
	for (SOCKET clientSocket : clientSockets) {
		if (clientSocket != excludeSocket)
		{ //Skip the sender

			int sendResult = SendFramedMessage(clientSocket, message);
			if (sendResult == SUCCESS) {
				successCount++;
			}
			else 
			 {
				failureCount++;
				LogMessage("Failed to send broadcast message to socket " + std::to_string(clientSocket) + " - Error: " + std::to_string(sendResult));
			}
		}
	}
	LogMessage("Broadcast completed - Success: " + std::to_string(successCount) + ", Failures: " + std::to_string(failureCount));

	// Return SUCCESS if at least one client received the message, or if no clients are connected
	return (successCount > 0 || clientSockets.size()) ? SUCCESS : MESSAGE_ERROR;
}

int Server::SendWelcomeMessage(SOCKET clientSocket)
{
	int result = SUCCESS;
	std::ostringstream welcomeMessage;
	welcomeMessage << "Welcome to Marcus' Spaghetti Relay Server!\n";
	welcomeMessage << "Commands start with '" << commandChar << "'\n";
	welcomeMessage << "Type '" << commandChar << "help' for available commands.\n";
	welcomeMessage << "Type '" << commandChar << "register <username> <password>' to register a new user.\n";
	welcomeMessage << "Example: "<< commandChar<< "~register john mypassord\n";
#if DEBUG_MODE
	LogMessage("Sending welcome message to client - Socket: " + std::to_string(clientSocket));
#endif // DEBUG_MODE
		result = SendFramedMessage(clientSocket, welcomeMessage.str());
	if (result != SUCCESS) {
		LogMessage("Failed to send welcome message - Error: " + std::to_string(result));
	}
	return result;
}

int Server::ProcessCommand(SOCKET clientSocket, const std::string& command)
{
	int result = SUCCESS;
#if DEBUG_MODE
	LogMessage("Processing command from client - Socket: " + std::to_string(clientSocket) + ", Command: " + command);
#endif // DEBUG_MODE
	//Parse command and parameters
	std::istringstream iss(command);
	std::string cmd;
	iss >> cmd;
	//Remove command characor for comparison
	if(!cmd.empty() && cmd[0] == commandChar) {
		cmd = cmd.substr(1); // Remove command character
	}
	else {
		LogMessage("Invalid command format - Missing command character");
		return PARAMETER_ERROR;
	}
	//Route to appropriate command handler
	if (cmd == "help")
	{
		result = HandleHelpCommand(clientSocket);
	}
	else if (cmd == "register")
	{
		std::string username, password;
		iss >> username >> password;
		if (username.empty() || password.empty()) {
			LogMessage("Invalid register command - Missing username or password");
			return PARAMETER_ERROR;
		}
		result = HandleRegisterCommand(clientSocket, username, password);
	}
	else
	{
		//Unknown command
		std::string errorMessage = "ERROR: Unknown command: " + cmd + ". Type '" + commandChar + "help' for available commands.";
		result = SendFramedMessage(clientSocket, errorMessage);
	}
	return result;
}

int Server::HandleHelpCommand(SOCKET clientSocket)
{
	int result = SUCCESS;
#if DEBUG_MODE
		LogMessage("Handling help command for client - Socket: " + std::to_string(clientSocket));
#endif // DEBUG_MODE
	std::ostringstream helpMessage;
	helpMessage << "Available commands:\n";
	helpMessage << commandChar << "help - Show this help message\n";
	helpMessage << commandChar << "register <username> <password> - Register a new user\n";
	helpMessage << "More commands available after login";
	result = SendFramedMessage(clientSocket, helpMessage.str());
	return result;
}

int Server::HandleRegisterCommand(SOCKET clientSocket, const std::string& username, const std::string& password)
{
	int result = SUCCESS;
#if DEBUG_MODE
	LogMessage("Handling register command for client - Socket: " + std::to_string(clientSocket) + ", Username: " + username);
#endif // DEBUG_MODE
	//Validate input parameters
	if(username.empty() || password.empty()) {
		std::string errorMessage = "ERROR: Usage:" + std::string(1, commandChar) + "register <username> <password>";
		result = SendFramedMessage(clientSocket, errorMessage);
	}
	else if (IsUserRegistered(username)) 
	{
	std::string errorMessage = "ERROR: User '" + username + "' is already registered. Please chooose a different username";
		result = SendFramedMessage(clientSocket, errorMessage);
	}
	else if(registeredClients.size()>= static_cast<size_t>(maxClients)) 
	{
		std::string errorMessage = "ERROR: Server at capacity (We Are Full To The Brim). Please try again later.";
		result = SendFramedMessage(clientSocket, errorMessage);
	}
	else 
	{
		//Create new user and add to registered clients
		UserAccount newUser(username, password, clientSocket); // Create new user account with username, password and socket
		registeredClients[username] = newUser; // Add to registered clients map
		//Log the successful registration
		LogMessage("User registered successfully - Username: " + username + ", Socket: " + std::to_string(clientSocket));
		//Create masked password for Display (showing only first and last character with X's in between)
		std::string maskedPassword = CreateMaskedPassword(password);
		std::string successMessage = "User '" + username + " (Password: " + maskedPassword + ")""' registered successfully! You can now login with your credentials.";
		result = SendFramedMessage(clientSocket, successMessage);
		//Broadcast registration message to all connected clients
		std::string broadcastMessage = "New user registered: " + username +" Make sure to reach out and say Hello";
		BroadcastToAllClients(broadcastMessage ,clientSocket);
		//Also Log the broadcast for server admin visibility
		LogMessage("Broadcasted registration message to all clients: " + broadcastMessage);
	}
	return result;
}

int Server::SendFramedMessage(SOCKET clientSocket, const std::string& message)
{
	int result = SUCCESS;
	if(!isSocketConnected(clientSocket)) {
		LogMessage("ERROR:Socket is not connected - Cannot send message");
		return DISCONNECT;
	}
	else if (message.length() > MAX_MESSAGE_SIZE) 
	{
		result = PARAMETER_ERROR;

	}
	else
	{
#if DEBUG_MODE
		LogMessage("Sending message to client - Socket: " + std::to_string(clientSocket) + ", Message: " + message);
#endif

		//Send message length first (1 byte)
		uint8_t messageLength = static_cast<uint8_t>(message.length());
		int lengthResult = send(clientSocket, (char*)&messageLength, sizeof(messageLength), 0);
		if (lengthResult == SOCKET_ERROR) {
			int error = getError();
			LogMessage("Failed to send message length - Error: " + std::to_string(error));
			result = DISCONNECT;
		}
		else
		{
			//Send message data using helpe function
			int dataResult = sendTcpData(clientSocket, message.c_str(), messageLength);
			if (dataResult != messageLength)
			{
				int error = getError();
				LogMessage("Message sent successfully to socket" + std::to_string(clientSocket));
				result = DISCONNECT;

			}
			else
			{
#if DEBUG_MODE
				LogMessage("Message sent successfully to socket " + std::to_string(clientSocket));
#endif // DEBUG_MODE
			}
		}
	}
	return result;
}
//Recieve message with TCP framing (1Bytelength +message)
int Server::RecieveFramedMessage(SOCKET clientSocket, char* buffer, int bufferSize)
{
	int result = SUCCESS;
	if (!isSocketConnected(clientSocket)) {
		LogMessage("ERROR: Socket is not connected - Cannot receive message");
		return DISCONNECT;
	}
	else
	{
		//First,receive message length (1 byte)
		uint8_t messageLength = 0;
		int lengthResult = recv(clientSocket, (char*)&messageLength, sizeof(messageLength), 0);
		if (lengthResult == 0) {
			//Client disconnected gracefully
			LogMessage("Client disconnected gracefully - Socket: " + std::to_string(clientSocket));
			return SHUTDOWN;
		}
		else if (lengthResult == SOCKET_ERROR)
		{
			int error = getError();
			if (error == WSAECONNRESET || error == WSAECONNABORTED)
			{
				result = SHUTDOWN;
				LogMessage("Client disconnected abruptly - Socket: " + std::to_string(clientSocket) + ", Error: " + std::to_string(error));
			}
			else {
				LogMessage("ERROR:Failed to receive message length - Error: " + std::to_string(error));
				result = DISCONNECT;
			}
		}
		else if (messageLength >= bufferSize)
		{
			LogMessage("ERROR:Received message length exceeds buffer size - Length: " + std::to_string(messageLength) + ", Buffer Size: " + std::to_string(bufferSize));
			result = PARAMETER_ERROR;
		}
		else {
			//Recieve the actual message with partial recieve loop
			int totalBytesReceived = 0;
			bool receivedCompleteMessage = false;
			while (totalBytesReceived < messageLength && !receivedCompleteMessage)
			{
				int partialResult = recv(clientSocket, buffer + totalBytesReceived, messageLength - totalBytesReceived, 0);
				if (partialResult == 0) {
					//Client disconnected gracefully
					result = SHUTDOWN;
					receivedCompleteMessage = true;
				}
				else if (partialResult == SOCKET_ERROR)
				{
					int error = getError();
					if (error == WSAECONNRESET || error == WSAECONNABORTED) {
						result = SHUTDOWN;
						LogMessage("Client disconnected abruptly - Socket: " + std::to_string(clientSocket) + ", Error: " + std::to_string(error));
					}
					else {
						LogMessage("ERROR:Failed to receive message data - Error: " + std::to_string(error));
						result = DISCONNECT;
					}
					receivedCompleteMessage = true;
				}
				else
				{
					totalBytesReceived += partialResult;

				}
			}
			if (result == SUCCESS)
			{
				//Null-terminate the received message
				buffer[messageLength] = '\0';
#if DEBUG_MODE
				LogMessage("Received framed message from client - Socket: " + std::to_string(clientSocket) + ", Message: " + std::string(buffer, messageLength));
#endif
			}
		}

	}
	return result;
}

bool Server::IsUserRegistered(const std::string& username)
{
	return registeredClients.find(username)!=registeredClients.end();
}

bool Server::isSocketConnected(SOCKET clientSocket)
{
	return clientSocket != INVALID_SOCKET;
}

void Server::RemoveClient(SOCKET clientSocket)
{
#if DEBUG_MODE
	LogMessage("Removing client - Socket: " + std::to_string(clientSocket));
#endif // DEBUG_MODE
	//Remove from the fd_set
	FD_CLR(clientSocket, &masterSet);
	//Remove from cliennt sockets vector 
	clientSockets.erase(std::remove(clientSockets.begin(), clientSockets.end(), clientSocket), clientSockets.end());
	//Remove from active clients if logged in 
	if(activeClients.find(clientSocket) != activeClients.end()) {

		std::string username = activeClients[clientSocket];
		activeClients.erase(clientSocket);
		//Update user's login status 
		if (registeredClients.find(username) != registeredClients.end()) {
			registeredClients[username].isLoggedIn = false;
			LogMessage("User logged out - Username: " + username + ", Socket: " + std::to_string(clientSocket));
		}
		else 
		{
			LogMessage("WARNING: User not found in registered clients - Username: " + username);
		}
	}
	//Close socket
	close(clientSocket);
	LogMessage("Closed client socket - Socket: " + std::to_string(clientSocket));

}

void Server::LogMessage(const std::string& message)
{
	std::cout << "[Server]" << message << std::endl;
}

std::string Server::GetServerIPAddress()
{
	std::ostringstream ipInfo;
	char hostname[256];
	//Get Hostname first
	if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR)
	{
		LogMessage("Warning: Failed to get hostname - Error: " + std::to_string(getError()));
		return "127.0.0.1"; // Default to localhost if hostname retrieval fails
	}
	LogMessage("Host name: " + std::string(hostname));

	struct addrinfo hints = {}, * info = nullptr, *ptr = nullptr;
		hints.ai_family = AF_INET; // IPv4
		hints.ai_socktype = SOCK_STREAM; // TCP socket
		hints.ai_flags = AI_PASSIVE; // For server application
		//Get address info for the hostname
		int addrResult = getaddrinfo(hostname, nullptr, &hints, &info);
		if (addrResult != 0) {
			LogMessage("Failed to get address info for hostname - Error: " + std::to_string(addrResult));
			return "127.0.0.1";
		}

		std::string primaryIPv4 = "127.0.0.1"; // Default fallback
		bool foundIPv4 = false;
		bool foundIPv6 = false;
		// Iterate through all addresses
		for (ptr = info; ptr != nullptr; ptr = ptr->ai_next)
		{
			char ip_str[INET_ADDRSTRLEN];
			if (ptr->ai_family == AF_INET)
			{ // IPv4
				struct sockaddr_in* sockaddr_ipv4 = (struct sockaddr_in*)info->ai_addr;
				inet_ntop(AF_INET, &sockaddr_ipv4->sin_addr, ip_str, INET_ADDRSTRLEN);
				if (!foundIPv4) {
					ipInfo << "IPv4 Address: " << ip_str << std::endl;
					primaryIPv4 = std::string(ip_str); // Store first found IPv4 address
					foundIPv4 = true;
				}
				else
				{
					ipInfo << "Additional IPv4 Address: " << ip_str << std::endl;
				}
			}
			else if (ptr->ai_family == AF_INET6)
			{ // IPv6
				struct sockaddr_in6* sockaddr_ipv6 = (struct sockaddr_in6*)info->ai_addr;
				inet_ntop(AF_INET6, &sockaddr_ipv6->sin6_addr, ip_str, INET_ADDRSTRLEN);
				//Skip loopback  and local addresses for cleaner output
				if (strncmp(ip_str, "::1", 3) != 0 && strncmp(ip_str, "fe80", 4) != 0)
				{
					if (!foundIPv6) {
						ipInfo << "IPv6 Address: " << ip_str << std::endl;
						foundIPv6 = true;
					}
					else
					{
						ipInfo << "Additional IPv6 Address: " << ip_str << std::endl;
					}
				}
			}
		}
		//Free address info structure
		freeaddrinfo(info);
		//Log all discovered addresses
		if(foundIPv4||foundIPv6) {
			LogMessage("Discovered server IP addresses:\n" + ipInfo.str());
		}
		else
		{
			LogMessage("No valid IP addresses found for server, using localhost.");
		}
		return primaryIPv4; // Return the first found IPv4 address as primary
}

