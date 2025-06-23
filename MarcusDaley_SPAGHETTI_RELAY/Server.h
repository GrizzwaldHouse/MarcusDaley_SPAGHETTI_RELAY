#pragma once
  
#include "platform.h" //For platform-specific definitions and types
#include "CommandMessages.h" //For command message handling
#include<vector> //For storing active client sockets
#include<unordered_map> //For storing user accounts and active clients
#include<sstream> //For string stream operations
#include <iostream> //For console output
#include <string> //For string manipulation
#include <fstream> //For file operations
#include <ctime> //For timestamping log entries
#include<iomanip> //For formatting timestamps

// CONFIGURATION CONSTANTS
#define DEBUG_MODE 1 //Toggle for verbose logging
#define DEFAULT_PORT 8080 //Default port for the server
#define DEFAULT_CAPACITY 10 //Default capacity for the quote system
#define DEFAULT_COMMAND_CHAR '~' //Character used to separate commands in messages
#define BUFFER_SIZE 256 //Size of the buffer for receiving messages
#define MAX_MESSAGE_SIZE 255//Maximum size of a message
#define COMMANDS_LOG_FILE "commands.log" //File to log commands
#define MESSAGES_LOG_FILE "messages.log" //File to log messages
#define MAX_LOGIN_ATTEMPTS 3 //Maximum number of login attempts allowed
class Server
{
	std::string GetCurrentTimestamp();
	struct UserAccount
	{
		std::string username;
		std::string password;
		std::string registrationTime; // When user registered
		bool isLoggedIn; // Track if the user is logged in
		bool isOnline; // Track if user is currently connected
		int loginAttempts; // Track failed login attempts
		std::string lastActivity; // Track user's last activity time
		SOCKET clientSocket; // Store the client's socket for communication

		UserAccount() : isLoggedIn(false), isOnline(false), loginAttempts(0), clientSocket(INVALID_SOCKET) {}
		
		UserAccount(const std::string& user, const std::string& pass,  SOCKET socket)
			: username(user), password(pass), isLoggedIn(false), isOnline(false),
			loginAttempts(0), clientSocket(socket) {
			registrationTime = ""; // Placeholder - will be set by server
			lastActivity = registrationTime;
		}
	};

	// User session state tracking
	struct ClientSession {
		std::string username;
		std::string lastCommand;
		std::string joinTime;
		bool isAuthenticated;
		int messageCount;

		ClientSession() : isAuthenticated(false), messageCount(0) {
			joinTime = "";
		}
	};


private:
	SOCKET listenSocket; //Main listening socket for incoming connections
	std::vector<SOCKET> clientSockets; //List of active client sockets
	std::unordered_map<std::string, UserAccount> registeredClients; //username -> password mapping
	std::unordered_map<SOCKET, std::string> activeClients; //socket -> username mapping
	std::unordered_map<SOCKET, ClientSession> clientSessions; //socket -> ClientSession mapping
	fd_set masterSet; // Master set of sockets for select()
	fd_set readySet; // Set of sockets to read from
	uint16_t serverPort; //Port number for the server
	int maxClients;//Maximum number of clients allowed
	char commandChar;

	bool serverRunning; //Flag to indicate if the server is running

	public:
		Server(); //Constructor to initialize the server
		~Server(); //Destructor to clean up resources

		//Server Setup
	int InitializeServer();  //Initialize TCP server components //Phase 1
	int PromptServerConfiguration(); //Prompt user for server configuration settings //Phase 1
	void DisplayServerInfo(); //Display server information such as IP address and port //Phase 1
	int RunServer(); //MAin server IP and part information //Phase 1
	void Shutdown();  //Graceful server shutdown //Phase 1
	int HandleNewConnection(); //Accept a new client connection  //Phase 1
	int HandleClientMessage(SOCKET clientSocket ); //Process a message from a client  Phase1-2
	
	// Welcome Message
	int SendWelcomeMessage(SOCKET clientSocket); //Phase 1
	
	// Command Processing 
	int ProcessCommand(SOCKET clientSocket, const std::string& command); //Phase 1
	int HandleHelpCommand(SOCKET clientSocket); //Phase 1
	int HandleRegisterCommand(SOCKET clientSocket, const std::string& username, const std::string& password); //Phase 1
	int HandleLoginCommand(SOCKET clientSocket, const std::string& username, const std::string& password); //Phase 2
	int HandleLogoutCommand(SOCKET clientSocket); //Phase 2
	int HandleGetListCommand(SOCKET clientSocket); //Phase 2
	int HandleGetLogCommand(SOCKET clientSocket); //Phase 2
	
	
	std::string CreateMaskedPassword(const std::string& password); //Mask the password for security
	int BroadcastToAllClients(const std::string& message ,SOCKET excludeSocket); //Broadcast a message to all connected clients Phase 3
	
	
	//Message Processing
	int SendFramedMessage(SOCKET clientSocket, const std::string& message); //Phase1
	int RecieveFramedMessage(SOCKET clientSocket, char* buffer, int  bufferSize); //Phase1
	int ProcessCommandMessage(SOCKET clientSocket, const std::string& message);
	// Message System
	int HandleSendCommand(SOCKET clientSocket, const std::string& recipient, const std::string& message);
	int SendDirectMessage(SOCKET senderSocket, const std::string& recipientUsername, const std::string& message);
	// Separate chat message processing
	int ProcessChatMessage(SOCKET clientSocket, const std::string& message);
	//Helper functions for user management
	bool IsUserRegistered(const std::string& username); //Phase 2
	bool isSocketConnected(SOCKET clientSocket); //Phase1
	bool IsUserLoggedIn(const std::string& username); //Phase 2
	bool IsUserAuthenticated(SOCKET clientSocket); //Phase 2
	void RemoveClient(SOCKET clientSocket); //Phase1
	void LogMessage(const std::string& message);//Phase 2
	void LogCommand(SOCKET clientSocket, const std::string& command); //Phase 2
	void LogPublicMessage(const std::string& senderName, const std::string& message); //Phase 2
//Phase 2
	std::string GetServerIPAddress();  //Phase 1


};