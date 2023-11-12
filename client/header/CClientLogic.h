/**
 * MessageU Client
 * @file CClientLogic.h
 * @brief The core logic of Client.
 * CClientLogic received commands from CClientMenu and invokes internal logic such as CFileHandler, CSocketHandler.
 * @author Roman Koifman
 * https://github.com/Romansko/MessageU/blob/main/client/header/CClientLogic.h
 */
#pragma once
#include "protocol.h"
#include <sstream>
#include <string>
#include <vector>

constexpr auto CLIENT_INFO = "me.info";   // Should be located near exe file.
constexpr auto SERVER_INFO = "transfer.info";  // Should be located near exe file.
constexpr auto PRIVATE_KEY_INFO = "priv.key";

class CFileHandler;
class CSocketHandler;
class RSAPrivateWrapper;

class CClientLogic
{
public:
	
	struct SClient
	{
		SClientID     id;
		std::string   username;
		SPublicKey    publicKey;
		bool          publicKeySet    = false;
		SSymmetricKey aes_symmetricKey;
		bool          aes_symmetricKeySet = false;
	};

	struct SMessage
	{
		std::string username; // source username
		std::string content;
	};

	struct SFile
	{
		std::string username; // source username
		size_t bytes;
		uint8_t* filecontent;
		std::string filePath;
		std::string fileName;
		size_t retryAttempts = 0;
		size_t checksum;
		bool shouldResend = false;
	};

public:
	CClientLogic();
	virtual ~CClientLogic();
	CClientLogic(const CClientLogic& other) = delete;
	CClientLogic(CClientLogic&& other) noexcept = delete;
	CClientLogic& operator=(const CClientLogic& other) = delete;
	CClientLogic& operator=(CClientLogic&& other) noexcept = delete;

	// inline getters
	std::string getLastError() const { return _lastError.str(); }
	std::string getSelfUsername() const { return _self.username; }
	SClientID   getSelfClientID() const { return _self.id; }
	
	// client logic to be invoked by client menu.
	bool parseServeInfo();
	bool parseClientInfo();
    bool parseNetworkInfo(std::string info);
	std::string readInputFromFile(const std::string filename, int lineNumber);
	std::vector<std::string> getUsernames() const;
	bool registerClient(const std::string& username);
	bool reconnectClient(const std::string& username);
	bool registerPublicKey();
	bool requestClientsList();
	bool requestClientPublicKey(const std::string& username);
	bool sendFile();
	bool retry();
	bool resendFile();
	bool ack_CRC_valid();
	bool nack_CRC_valid();

private:
	void clearLastError();
	bool storeClientInfo();
	bool storeRSAInfo(std::string& private_key);
	bool validateHeader(const SResponseHeader& header, const EResponseCode expectedCode);
	bool validateFileName(std::string& fileName);
	bool receiveUnknownPayload(const uint8_t* const request, const size_t reqSize, const EResponseCode expectedCode, uint8_t*& payload, size_t& size);
	bool setClientPublicKey(const SClientID& clientID, const SPublicKey& publicKey);
	bool setClientSymmetricKey(const SClientID& clientID, const SSymmetricKey& symmetricKey);
	bool getClient(const std::string& username, SClient& client) const;
	bool getClient(const SClientID& clientID, SClient& client) const;
	void getPrivateKeyfromKeyFile(const std::string filepath, std::string& privKey);


	SClient              _self;           // self symmetric key invalid.
	SFile				_fileToBeSent;
	std::vector<SClient> _clients;
	std::stringstream    _lastError;
	CFileHandler*        _fileHandler;
	CSocketHandler*      _socketHandler;
	RSAPrivateWrapper*   _rsaDecryptor;
};
