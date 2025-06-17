#include <iostream>
#include <cstdlib>
#include "platform.h"
#include "CommandMessages.h"
#include "Server.h"





int main() 
{
	std::cout << "Starting MarcusDaley_SPAGHETTI_RELAY..." << std::endl;
//Step 1:Initialize the Winstock 
	std::cout << "Initializing Winsock..." << std::endl;
	if(startup()!=0) {
		std::cerr << "Failed to initialize Winsock." << std::endl;

		return EXIT_FAILURE;
	}
	std::cout << "[Success] Winsock initialized successfully." << std::endl;
	//Step 2 Create the server intance
	std::cout << "Creating server instance..." << std::endl;
	Server server;
	//Step 3: Prompt for server configuration
	std::cout << "Configuring server settings..." << std::endl;
	int ConfigResult = server.PromptServerConfiguration();
	if(ConfigResult != SUCCESS) {
		std::cerr << "Failed to configure server settings. Error code: " << ConfigResult << std::endl;
		shutdown();
		return EXIT_FAILURE;
	}

	//Step 4: Initialize the server components
	std::cout << "Initializing server components..." << std::endl;
	int initResult = server.InitializeServer();
	if (initResult != SUCCESS)
	{
				std::cerr << "Failed to initialize server components. Error code: " << initResult << std::endl;
				shutdown();
				return EXIT_FAILURE;
	}
	//Step 5:Display server information
	std::cout << "\n[INFO] Server initalization complete." << std::endl;
	server.DisplayServerInfo();
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
	std::cout << "\n[SHUTDOWN] Shutting down server..." << std::endl;
	server.Shutdown();
	std::cout << "[CLEANUP] Cleaning up Winsock..." << std::endl;
	if (shutdown() != 0)
	{
		std::cerr << "[WARNING] Winsock cleanup encountered issues. " << std::endl;
		std::cerr << "Error Code:  " << getError() << std::endl;
	}
	std::cout << "[COMPLETE] Server shutdown complete." << std::endl;
	std::cout << "===  MarcusDaley_SPAGHETTI_RELAY has stopped ===" << std::endl;
	return EXIT_SUCCESS;


	}


