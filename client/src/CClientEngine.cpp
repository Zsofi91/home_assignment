#include "CClientEngine.h"
#include <iostream>
#include <boost/algorithm/string/trim.hpp>

/**
 * Print error and exit client.
 */
void CClientEngine::clientStop(const std::string& error) const
{
	std::cout << "Fatal Error: " << error << std::endl << "Client will stop." << std::endl;
	pause();
	exit(1);
}

/**
 * Initialize client's engine & its internals.
 */
void CClientEngine::initialize()
{
	if (!_clientLogic.parseServeInfo())
	{
		clientStop(_clientLogic.getLastError());
	}
	_registered = _clientLogic.parseClientInfo();

}

/**
 * Print main message to the screen.
 */
void CClientEngine::display() const
{
	clear();
	if (_registered && !_clientLogic.getSelfUsername().empty())
		std::cout << "Hello " << _clientLogic.getSelfUsername() << ", ";
}

/**
 * Invoke matching function to user's choice. User's choice is validated.
 */
void CClientEngine::startFlow()
{
	const std::string username;
	if (!_registered)
	{
		username = readInputFromFile(SERVER_INFO, 2);
		registration_success = _clientLogic.registerClient(username);
		
		if (!registration_success)
			return false;
		else
			_registered = registration_success;

		publicKey_registration = _clientLogic.registerPublicKey();
	}
	else
	{
		username = readInputFromFile(CLIENT_INFO, 1);
		success = _clientLogic.reconnectClient(username);
		if (!success)
			return false;
	}

	_clientLogic.sendFile();



	// Main selection switch
	switch (menuOption.getValue())
	{
	case CMenuOption::EOption::MENU_EXIT:
	{
		std::cout << "Client will now exit." << std::endl;
		pause();
		exit(0);
	}
	case CMenuOption::EOption::MENU_REGISTER:
	{
		if (_registered)
		{
			std::cout << _clientLogic.getSelfUsername() << ", you have already registered!" << std::endl;
			return;
		}
        const std::string username;
        try
        {
            username = readInputFromFile(CLIENT_INFO, 1);
        }
        catch (const std::exception& e)
        {
            username = readInputFromFile(SERVER_INFO, 2);
        }
		success = _clientLogic.registerClient(username);
		_registered = success;
		break;
	}
	case CMenuOption::EOption::MENU_REGISTER_PUBLIC_KEY:
	{
		username = readInputFromFile(CLIENT_INFO, 1);
		success = _clientLogic.registerPublicKey(username);
	}
	case CMenuOption::EOption::MENU_REQ_CLIENT_LIST:
	{
		success = _clientLogic.requestClientsList();
		if (success)
		{
			// Copy usernames into vector & sort them alphabetically.
			std::vector<std::string> usernames = _clientLogic.getUsernames();
			if (usernames.empty())
			{
				std::cout << "Server has no users registered." << std::endl;
				return;
			}
			std::cout << "Registered users:" << std::endl;
			for (const auto& username : usernames )
			{
				std::cout << username << std::endl;
			}
		}
		break;
	}
	case CMenuOption::EOption::MENU_REQ_PUBLIC_KEY:
	{
		const std::string username = readUserInput("Please type a username..");
		success = _clientLogic.requestClientPublicKey(username);
		break;
	}
	case CMenuOption::EOption::MENU_REQ_PENDING_MSG:
	{
		std::vector<CClientLogic::SMessage> messages;
		success = _clientLogic.requestPendingMessages(messages);
		if (success)
		{
			std::cout << std::endl;
			for (const auto& msg : messages)
			{
				std::cout << "From: " << msg.username << std::endl << "Content:" << std::endl << msg.content << std::endl << std::endl;
			}
			const std::string lastErr = _clientLogic.getLastError();  // contains a string of errors occurred during messages parsing.
			if (!lastErr.empty())
			{
				std::cout << std::endl << "MESSAGES ERROR LOG: " << std::endl << lastErr;
			}
		}
		break;
	}
	case CMenuOption::EOption::MENU_SEND_MSG:
	{
		const std::string username = readUserInput("Please type a username to send message to..");
		const std::string message  = readUserInput("Enter message: ");
		success = _clientLogic.sendMessage(username, MSG_TEXT, message);
		break;
	}
	case CMenuOption::EOption::MENU_REQ_SYM_KEY:
	{
		const std::string username = readUserInput("Please type a username to request symmetric key from..");
		success = _clientLogic.sendMessage(username, MSG_SYMMETRIC_KEY_REQUEST);
		break;
	}
	case CMenuOption::EOption::MENU_SEND_SYM_KEY:
	{
		const std::string username = readUserInput("Please type a username to send symmetric key to..");
		success = _clientLogic.sendMessage(username, MSG_SYMMETRIC_KEY_SEND);
		break;
	}
	case CMenuOption::EOption::MENU_SEND_FILE:
	{
		const std::string username = readUserInput("Please type a username to send file to..");
		const std::string message  = readUserInput("Enter filepath: ");
		success = _clientLogic.sendMessage(username, MSG_FILE, message);
		break;
	}
	}

	std::cout << (success ? menuOption.getSuccessString() : _clientLogic.getLastError()) << std::endl;
}
