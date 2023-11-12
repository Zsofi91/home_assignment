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
	bool success;
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

	if (_clientLogic.sendFile())
	{
		success = _clientLogic.retry();
		if (success)
			_clientLogic.ack_CRC_valid();
		else
			_clientLogic.nack_CRC_valid();
	}
}
