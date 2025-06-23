#include <iostream>
#include <cstdlib>
#include "platform.h"
#include "CommandMessages.h"
#include "Server.h"



Server* globalServer = nullptr;

int main() 
{
	// Display startup banner
	std::cout << "==========================================" << std::endl;
	std::cout << "  MarcusDaley SPAGHETTI RELAY SERVER" << std::endl;
	std::cout << "           Phase 2 - Full Featured" << std::endl;
	std::cout << "==========================================" << std::endl;
	std::cout << "Starting server initialization..." << std::endl;

//Step 1:Initialize the Winstock 
	std::cout << "\n[STEP 1] Initializing Winsock..." << std::endl;
	if(startup()!=0) {
		std::cerr << "Failed to initialize Winsock." << std::endl;
		std::cerr << "[ERROR] Error code: " << getError() << std::endl;
		return EXIT_FAILURE;
	}
	std::cout << "[Success] Winsock initialized successfully." << std::endl;
	//Step 2 Create the server intance
	std::cout << "\n[STEP 2] Creating server instance..." << std::endl;
	Server server;
	globalServer = &server;
	//Step 3: Prompt for server configuration
	std::cout << "\n[STEP 3] Configuring server settings..." << std::endl;
	int configResult = server.PromptServerConfiguration();
	if(configResult != SUCCESS) {
		std::cerr << "Failed to configure server settings. Error code: " << configResult << std::endl;
		std::cerr << "[ERROR] Error code: " << configResult << std::endl;
		shutdown();
		return EXIT_FAILURE;
	}

	//Step 4: Initialize the server components
	std::cout << "\n[STEP 4] Initializing server components..." << std::endl;
	int initResult = server.InitializeServer();
	if (initResult != SUCCESS)
	{
				std::cerr << "Failed to initialize server components. Error code: " << initResult << std::endl;
				std::cerr << "[ERROR] Error code: " << initResult << std::endl;
				std::cerr << "[ERROR] Check if port is already in use or requires admin privileges." << std::endl;

				shutdown();
				return EXIT_FAILURE;
	}
	std::cout << "[SUCCESS] Server components initialized successfully." << std::endl;
	//Step 5:Display server information
	std::cout << "\n[STEP 5] Server initialization complete." << std::endl;
	server.DisplayServerInfo();
	// Step 6: Display Phase 2 features
	std::cout << "\n[PHASE 2 FEATURES]" << std::endl;
	std::cout << "- User Registration & Authentication" << std::endl;
	std::cout << "- Session Management with Login/Logout" << std::endl;
	std::cout << "- Private Messaging System" << std::endl;
	std::cout << "- Dual Logging (Commands & Messages)" << std::endl;
	std::cout << "- Enhanced Security & Validation" << std::endl;
	std::cout << "- Real-time User List Management" << std::endl;
	std::cout << "- Message History Retrieval" << std::endl;

	// Step 7: Start the server operation
	std::cout << "\n[STEP 6] Starting server operation..." << std::endl;
	std::cout << "[INFO] Server is now ready to accept connections." << std::endl;
	std::cout << "[INFO] Press Ctrl+C to stop the server gracefully." << std::endl;
	std::cout << "[INFO] Log files will be created: commands.log, messages.log" << std::endl;
	std::cout << "\n[RUNNING] Server main loop started..." << std::endl;

	//Step 6: Start the server operation
	std::cout << "\n[START] Starting server operation..." << std::endl;
	std::cout << "Press Ctrl+C to stop the server." << std::endl;
	int runResult = server.RunServer();
	if (runResult != SUCCESS) {
		std::cerr << "[ERROR] Server encountered an error during operation. Error code: " << runResult << std::endl;
		shutdown();
		return EXIT_FAILURE;
	}
	//Step 7: Cleanup and shutdown
	std::cout << "\n[STEP 7] Server stopped normally." << std::endl;
	std::cout << "\n[SHUTDOWN] Shutting down server..." << std::endl;
	server.Shutdown();
	std::cout << "[CLEANUP] Cleaning up Winsock..." << std::endl;
	if (shutdown() != 0)
	{
		std::cerr << "[WARNING] Winsock cleanup encountered issues. " << std::endl;
		std::cerr << "Error Code:  " << getError() << std::endl;
	}
	else
	{
		std::cout << "[SUCCESS] Winsock cleaned up successfully." << std::endl;
	}
	//Final status message
	std::cout << "\n[COMPLETE] Server shutdown complete." << std::endl;
	std::cout << "==========================================" << std::endl;
	std::cout << "  MarcusDaley SPAGHETTI RELAY STOPPED" << std::endl;
	std::cout << "==========================================" << std::endl;

	std::cout << "[COMPLETE] Server shutdown complete." << std::endl;
	std::cout << "===  MarcusDaley_SPAGHETTI_RELAY has stopped ===" << std::endl;

	// Reset global reference
	globalServer = nullptr;
	return EXIT_SUCCESS;


	}


