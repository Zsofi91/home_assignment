/**
 * MessageU Client
 * @file CClientLogic.cpp
 * @brief The core logic of Client.
 * CClientLogic received commands from CClientMenu and invokes internal logic such as CFileHandler, CSocketHandler.
 * @author Roman Koifman
 * https://github.com/Romansko/MessageU/blob/main/client/src/CClientLogic.cpp
 */
#include "CClientLogic.h"
#include "CStringer.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "CFileHandler.h"
#include "CSocketHandler.h"
#include "Checksum.h"

std::ostream& operator<<(std::ostream& os, const EMessageType& type)
{
	os << static_cast<messageType_t>(type);
	return os;
}

CClientLogic::CClientLogic() : _fileHandler(nullptr), _socketHandler(nullptr), _rsaDecryptor(nullptr)
{
	_fileHandler = new CFileHandler();
	_socketHandler = new CSocketHandler();
}

CClientLogic::~CClientLogic()
{
	delete _fileHandler;
	delete _socketHandler;
	delete _rsaDecryptor;
}

/**
 * Parse SERVER_INFO file for server address & port.
 */
bool CClientLogic::parseServeInfo()
{
	std::stringstream err;
	if (!_fileHandler->open(SERVER_INFO))
	{
		clearLastError();
		_lastError << "Couldn't open " << SERVER_INFO;
		return false;
	}
	std::string network_info;
	if (!_fileHandler->readLine(network_info))
	{
		clearLastError();
		_lastError << "Couldn't read " << SERVER_INFO;
		return false;
	}
	if (!parseNetworkInfo(network_info))
		return false;

	std::string name;
	std::string filePath;

	if (!_fileHandler->readLine(name))
	{
		clearLastError();
		_lastError << "Couldn't read " << SERVER_INFO;
		return false;
	}
	CStringer::trim(name);
	if (name.length() >= CLIENT_NAME_SIZE)
	{
		clearLastError();
		_lastError << "Invalid username read from " << SERVER_INFO;
		return false;
	}
	_self.username = name;
	if (!_fileHandler->readLine(filePath))
	{
		clearLastError();
		_lastError << "Couldn't read " << SERVER_INFO;
		return false;
	}
	if (!validateFileName(filePath))
	{
		clearLastError();
		_lastError << "Invalid filename from " << SERVER_INFO;
		return false;
	}
	_fileHandler->close();
	if (! _fileHandler->readAtOnce(filePath, _fileToBeSent.filecontent, _fileToBeSent.bytes))
	{
		clearLastError();
		_lastError << "Could not open file " << filePath;
		return false;
	}
	_fileToBeSent.filePath = filePath;
	//_fileHandler->close();
	return true;
}

/**
 * Parse CLIENT_INFO file.
 */
bool CClientLogic::parseClientInfo()
{
	std::string line;
	if (!_fileHandler->open(CLIENT_INFO))
	{
		clearLastError();
		_lastError << "Couldn't open " << CLIENT_INFO;
		return false;
	}

	// Read & Parse username
	if (!_fileHandler->readLine(line))
	{
		clearLastError();
		_lastError << "Couldn't read username from " << CLIENT_INFO;
		return false;
	}
	CStringer::trim(line);
	if (line.length() >= CLIENT_NAME_SIZE)
	{
		clearLastError();
		_lastError << "Invalid username read from " << CLIENT_INFO;
		return false;
	}
	_self.username = line;

	// Read & Parse Client's UUID.
	if (!_fileHandler->readLine(line))
	{
		clearLastError();
		_lastError << "Couldn't read client's UUID from " << CLIENT_INFO;
		return false;
	}

	line = CStringer::unhex(line);
	const char* unhexed = line.c_str();
	if (strlen(unhexed) != sizeof(_self.id.uuid))
	{
		memset(_self.id.uuid, 0, sizeof(_self.id.uuid));
		clearLastError();
		_lastError << "Couldn't parse client's UUID from " << CLIENT_INFO;
		return false;
	}
	memcpy(_self.id.uuid, unhexed, sizeof(_self.id.uuid));

	// Read & Parse Client's private key.
	std::string decodedKey;
	while (_fileHandler->readLine(line))
	{
		decodedKey.append(CStringer::decodeBase64(line));
	}
	if (decodedKey.empty())
	{
		clearLastError();
		_lastError << "Couldn't read client's private key from " << CLIENT_INFO;
		return false;
	}
	try
	{
		delete _rsaDecryptor;
		_rsaDecryptor = new RSAPrivateWrapper(decodedKey);
	}
	catch (...)
	{
		clearLastError();
		_lastError << "Couldn't parse private key from " << CLIENT_INFO;
		return false;
	}
	_fileHandler->close();
	return true;
}

bool CClientLogic::parseNetworkInfo(std::string info)
{
	CStringer::trim(info);
	const auto pos = info.find(':');
	if (pos == std::string::npos)
	{
		clearLastError();
		_lastError << SERVER_INFO << " has invalid format! missing separator ':'";
		return false;
	}
	const auto address = info.substr(0, pos);
	const auto port = info.substr(pos + 1);

	if (!_socketHandler->setSocketInfo(address, port))
	{
		clearLastError();
		_lastError << SERVER_INFO << " has invalid IP address or port!";
		return false;
	}
	return true;
}

/**
 * Copy usernames into vector & sort them alphabetically.
 * If _clients is empty, an empty vector will be returned.
 */
std::vector<std::string> CClientLogic::getUsernames() const
{
	std::vector<std::string> usernames(_clients.size());
	std::transform(_clients.begin(), _clients.end(), usernames.begin(),
		[](const SClient& client) { return client.username; });
	std::sort(usernames.begin(), usernames.end());
	return usernames;
}

/**
 * Reset _lastError StringStream: Empty string, clear errors flag and reset formatting.
 */
void CClientLogic::clearLastError()
{
	const std::stringstream clean;
	_lastError.str("");
	_lastError.clear();
	_lastError.copyfmt(clean);
}

/**
 * Store client info to CLIENT_INFO file.
 */
bool CClientLogic::storeClientInfo()
{
	if (!_fileHandler->open(CLIENT_INFO, true))
	{
		clearLastError();
		_lastError << "Couldn't open " << CLIENT_INFO;
		return false;
	}

	// Write username
	if (!_fileHandler->writeLine(_self.username))
	{
		clearLastError();
		_lastError << "Couldn't write username to " << CLIENT_INFO;
		return false;
	}

	// Write UUID.
	const auto hexifiedUUID = CStringer::hex(_self.id.uuid, sizeof(_self.id.uuid));
	if (!_fileHandler->writeLine(hexifiedUUID))
	{
		clearLastError();
		_lastError << "Couldn't write UUID to " << CLIENT_INFO;
		return false;
	}
	_fileHandler->close();
	return true;
}

/**
 * Validate SResponseHeader upon an expected EResponseCode.
 */
bool CClientLogic::validateHeader(const SResponseHeader& header, const EResponseCode expectedCode)
{
	// Error validation
	csize_t expectedSize = DEF_VAL; 
	for (auto error : { EResponseErrorCodes::REGISTRATION_RESPONSE_ERROR,
						EResponseErrorCodes::RESPONSE_ERROR,
						EResponseErrorCodes::RE_REGISTRATION_RESPONSE_ERROR })
	{
		if (error == header.code)
		{
			clearLastError();
			_lastError << "Error response code (" << error << ") received.";
			return false;
		}
	}

	if (header.code != expectedCode)
	{
		clearLastError();
		_lastError << "Unexpected response code " << header.code << " received. Expected code was " << expectedCode;
		return false;
	}

	//csize_t expectedSize = DEF_VAL;
	switch (header.code)
	{
	case RESPONSE_REGISTRATION:
	{
		expectedSize = sizeof(SResponseRegistration) - sizeof(SResponseHeader);
		break;
	}
	case RESPONSE_PUBLIC_KEY_REGISTRATION:
	{
		expectedSize = sizeof(SResponsePublicKeyRegistration) - sizeof(SResponseHeader);
		break;
	}
	case RESPONSE_PUBLIC_KEY:
	{
		expectedSize = sizeof(SResponsePublicKey) - sizeof(SResponseHeader);
		break;
	}
	case RESPONSE_FILE_SENT:
	{
		expectedSize = sizeof(SResponseFileSent) - sizeof(SResponseHeader);
		break;
	}
	default:
	{
		return true;  // variable payload size. 
	}
	}

	if (header.payloadSize != expectedSize)
	{
		clearLastError();
		_lastError << "Unexpected payload size " << header.payloadSize << ". Expected size was " << expectedSize;
		return false;
	}
	return true;
}

bool CClientLogic::validateFileName(std::string& filePath)
{
	CStringer::trim(filePath);
	const auto pos = filePath.rfind('\\');
	const auto fileName = filePath.substr(pos + 1);
	if (fileName.length() >= FILE_NAME_SIZE)
	{
		clearLastError();
		_lastError << "Invalid filename from " << SERVER_INFO;
		return false;
	}
	_fileToBeSent.fileName = fileName;
	return true;

}

/**
 * Receive unknown payload. Payload size is parsed from header.
 * Caller responsible for deleting payload upon success.
 */
bool CClientLogic::receiveUnknownPayload(const uint8_t* const request, const size_t reqSize, const EResponseCode expectedCode, uint8_t*& payload, size_t& size)
{
	SResponseHeader response;
	uint8_t buffer[PACKET_SIZE];
	payload = nullptr;
	size = 0;
	if (request == nullptr || reqSize == 0)
	{
		clearLastError();
		_lastError << "Invalid request was provided";
		return false;
	}
	if (!_socketHandler->connect())
	{
		clearLastError();
		_lastError << "Failed connecting to server on " << _socketHandler;
		return false;
	}
	if (!_socketHandler->send(request, reqSize))
	{
		_socketHandler->close();
		clearLastError();
		_lastError << "Failed sending request to server on " << _socketHandler;
		return false;
	}
	if (!_socketHandler->receive(buffer, sizeof(buffer)))
	{
		clearLastError();
		_lastError << "Failed receiving response header from server on " << _socketHandler;
		return false;
	}
	memcpy(&response, buffer, sizeof(SResponseHeader));
	if (!validateHeader(response, expectedCode))
	{
		clearLastError();
		_lastError << "Received unexpected response code from server on  " << _socketHandler;
		return false;
	}
	if (response.payloadSize == 0)
		return true;  // no payload. but not an error.

	size = response.payloadSize;
	payload = new uint8_t[size];
	uint8_t* ptr = static_cast<uint8_t*>(buffer) + sizeof(SResponseHeader);
	size_t recSize = sizeof(buffer) - sizeof(SResponseHeader);
	if (recSize > size)
		recSize = size;
	memcpy(payload, ptr, recSize);
	ptr = payload + recSize;
	while (recSize < size)
	{
		size_t toRead = (size - recSize);
		if (toRead > PACKET_SIZE)
			toRead = PACKET_SIZE;
		if (!_socketHandler->receive(buffer, toRead))
		{
			clearLastError();
			_lastError << "Failed receiving payload data from server on " << _socketHandler;
			delete[] payload;
			payload = nullptr;
			size = 0;
			return false;
		}
		memcpy(ptr, buffer, toRead);
		recSize += toRead;
		ptr += toRead;
	}

	return true;
}

/**
 * Store a client's public key on RAM.
 */
bool CClientLogic::setClientPublicKey(const SClientID& clientID, const SPublicKey& publicKey)
{
	for (SClient& client : _clients)
	{
		if (client.id == clientID)
		{
			client.publicKey = publicKey;
			client.publicKeySet = true;
			return true;
		}
	}
	return false;
}


/**
 * Register client via the server.
 */
bool CClientLogic::registerClient(const std::string& username)
{
	SRequestRegistration  request;
	SResponseRegistration response;

	if (username.length() >= CLIENT_NAME_SIZE)  // >= because of null termination.
	{
		clearLastError();
		_lastError << "Invalid username length!";
		return false;
	}
		
	// fill request data
	request.header.payloadSize = sizeof(request.payload);
	strcpy_s(reinterpret_cast<char*>(request.payload.Name.name), CLIENT_NAME_SIZE, username.c_str());

	if (!_socketHandler->sendReceive(reinterpret_cast<const uint8_t* const>(&request), sizeof(request),
		reinterpret_cast<uint8_t* const>(&response), sizeof(response)))
	{
		clearLastError();
		_lastError << "Failed communicating with server on " << _socketHandler;
		return false;
	}

	// parse and validate SResponseRegistration
	if (!validateHeader(response.header, RESPONSE_REGISTRATION))
		return false;  // error message updated within.

	// store received client's ID
	_self.id = response.payload;
	_self.username = username;

	if (!storeClientInfo())
	{
		clearLastError();
		_lastError << "Failed writing client info to " << CLIENT_INFO << ". Please register again with different username.";
		return false;
	}
	return true;
}
bool CClientLogic::reconnectClient(const std::string& username)
{
	SRequestReconnect request;
	SResponseReconnect response;

	request.header.payloadSize = sizeof(request.payload);
	strcpy_s(reinterpret_cast<char*>(request.payload.Name.name), CLIENT_NAME_SIZE, username.c_str());

	if (!_socketHandler->sendReceive(reinterpret_cast<const uint8_t* const>(&request), sizeof(request),
		reinterpret_cast<uint8_t* const>(&response), sizeof(response)))
	{
		clearLastError();
		_lastError << "Failed communicating with server on " << _socketHandler;
		return false;
	}

	if (!validateHeader(response.header, RESPONSE_RECONNECTION))
		return false;  // error message updated within.

	// store the decrypted AES key using the priv.key file
	std::string privateKey;
	getPrivateKeyfromKeyFile(PRIVATE_KEY_INFO, privateKey);
	try
	{
		delete _rsaDecryptor;
		_rsaDecryptor = new RSAPrivateWrapper(privateKey);
	}
	catch (...)
	{
		clearLastError();
		_lastError << "Couldn't parse private key from " << CLIENT_INFO;
		return false;
	}
	_self.id = response.payload.clientId;
	std::string decrypted_key = _rsaDecryptor->decrypt(response.payload.aes_symmetricKey.symmetricKey, sizeof(response.payload.aes_symmetricKey.symmetricKey));
	memcpy(_self.aes_symmetricKey.symmetricKey, decrypted_key.c_str(), decrypted_key.size());
	_self.aes_symmetricKeySet = true;
	return true;

}
bool CClientLogic::storeRSAInfo(std::string& private_key)
{
	if (!_fileHandler->writeAtOnce(PRIVATE_KEY_INFO, private_key))
	{
		clearLastError();
		_lastError << "Couldn't write client's private key to " << PRIVATE_KEY_INFO;
		return false;
	}
	return true;
}
bool CClientLogic::registerPublicKey()
{
	SRequestPublicKeyRegistration request;
	SResponsePublicKeyRegistration response;

	delete _rsaDecryptor;
	_rsaDecryptor = new RSAPrivateWrapper();
	const auto publicKey = _rsaDecryptor->getPublicKey();
	if (publicKey.size() != PUBLIC_KEY_SIZE)
	{
		clearLastError();
		_lastError << "Invalid public key length!";
		return false;
	}
	auto privateKey = _rsaDecryptor->getPrivateKey();
	if (storeRSAInfo(privateKey)) // If you had to create a new file, write the encrypted key to me.info
	{
		// Write Base64 encoded private key
		const auto encodedKey = CStringer::encodeBase64(_rsaDecryptor->getPrivateKey());
		uint8_t* temp;
		size_t file_size = CLIENT_NAME_SIZE + CLIENT_ID_SIZE;
		if (!_fileHandler->readAtOnce(CLIENT_INFO, temp, file_size))
		{
			clearLastError();
			_lastError << "Could not open file " << CLIENT_INFO;
			return false;
		}
		const uint8_t* extra_key = reinterpret_cast<const uint8_t* const>(encodedKey.c_str(), encodedKey.size());

		memcpy(temp + sizeof(temp), extra_key, sizeof(extra_key));
		
		if (!_fileHandler->writeAtOnce(CLIENT_INFO, temp))
		{
			clearLastError();
			_lastError << "Couldn't write client's private key to " << CLIENT_INFO;
			return false;
		}
	}
	request.header.payloadSize = sizeof(request.payload);
	memcpy(request.payload.clientPublicKey.publicKey, publicKey.c_str(), sizeof(request.payload.clientPublicKey.publicKey));
	strcpy_s(reinterpret_cast<char*>(request.payload.Name.name), CLIENT_NAME_SIZE, _self.username.c_str());
	if (!_socketHandler->sendReceive(reinterpret_cast<const uint8_t* const>(&request), sizeof(request),
		reinterpret_cast<uint8_t* const>(&response), sizeof(response)))
	{
		clearLastError();
		_lastError << "Failed communicating with server on " << _socketHandler;
		return false;
	}
	if (!validateHeader(response.header, RESPONSE_PUBLIC_KEY_REGISTRATION))
		return false;  // error message updated within.

	// store the AES key
	std::string decrypted_key = _rsaDecryptor->decrypt(response.payload.aes_symmetricKey.symmetricKey, sizeof(response.payload.aes_symmetricKey.symmetricKey));
	memcpy(_self.aes_symmetricKey.symmetricKey, decrypted_key.c_str(), decrypted_key.size());
	_self.aes_symmetricKeySet = true;
	_self.aes_symmetricKeySet = true;
	return true;
}

bool CClientLogic::sendFile()
{
	SRequestSendFile  request(_self.id);
	SResponseFileSent response;
	uint8_t* content = nullptr;
	
	if (_fileToBeSent.bytes == 0)
	{
		clearLastError();
		_lastError << "Empty input was provided!";
		return false;
	}
	if (!_self.aes_symmetricKeySet)
	{
		clearLastError();
		_lastError << "Couldn't find " << _self.username << "'s aes key.";
		return false;
	}

	strcpy_s(reinterpret_cast<char*>(request.payloadHeader.fileName.name), CLIENT_NAME_SIZE, _fileToBeSent.fileName.c_str());
	_fileToBeSent.checksum = checksumFromFile(_fileToBeSent.filePath);

	AESWrapper aes(_self.aes_symmetricKey);
	const std::string encrypted = aes.encrypt(_fileToBeSent.filecontent, _fileToBeSent.bytes);

	request.payloadHeader.contentSize = encrypted.size();
	content = new uint8_t[request.payloadHeader.contentSize];
	memcpy(content, encrypted.c_str(), request.payloadHeader.contentSize);

	// prepare message to send
	size_t msgSize;
	uint8_t* msgToSend;
	request.header.payloadSize = sizeof(request.payloadHeader) + request.payloadHeader.contentSize;
	if (content == nullptr)
	{
		msgToSend = reinterpret_cast<uint8_t*>(&request);
		msgSize = sizeof(request);
	}
	else
	{
		msgToSend = new uint8_t[sizeof(request) + request.payloadHeader.contentSize];
		memcpy(msgToSend, &request, sizeof(request));
		memcpy(msgToSend + sizeof(request), content, request.payloadHeader.contentSize);
		msgSize = sizeof(request) + request.payloadHeader.contentSize;
	}

	// send request and receive response
	if (!_socketHandler->sendReceive(msgToSend, msgSize, reinterpret_cast<uint8_t* const>(&response), sizeof(response)))
	{
		delete[] content;
		if (msgToSend != reinterpret_cast<uint8_t*>(&request))
			delete[] msgToSend;
		clearLastError();
		_lastError << "Failed communicating with server on " << _socketHandler;
		return false;
	}

	delete[] content;

	if (!validateHeader(response.header, RESPONSE_FILE_SENT))
		return false;  // error message updated within.

	++_fileToBeSent.retryAttempts;
	_fileToBeSent.shouldResend = !compareCRC(response.payload.checksum);
	return true;
}

bool CClientLogic::resendFile()
{
	// send 1030
	SRequestInvalidCRC request;
	SResponseGeneric response;

	request.header.payloadSize = sizeof(request.payload);
	strcpy_s(reinterpret_cast<char*>(request.payload.filename.name), FILE_NAME_SIZE, _fileToBeSent.fileName.c_str());

	if (!_socketHandler->sendReceive(reinterpret_cast<const uint8_t* const>(&request), sizeof(request),
		reinterpret_cast<uint8_t* const>(&response), sizeof(response)))
	{
		clearLastError();
		_lastError << "Failed communicating with server on " << _socketHandler;
		return false;
	}

	if (!validateHeader(response.header, RESPONSE_ACK))
		return false;  // error message updated within.

	// send 1028
	this->sendFile();
	return true;
}

bool CClientLogic::ack_CRC_valid()
{
	SRequestValidCRC request;
	SResponseGeneric response;

	request.header.payloadSize = sizeof(request.payload);
	strcpy_s(reinterpret_cast<char*>(request.payload.filename.name), FILE_NAME_SIZE, _fileToBeSent.fileName.c_str());

	if (!_socketHandler->sendReceive(reinterpret_cast<const uint8_t* const>(&request), sizeof(request),
		reinterpret_cast<uint8_t* const>(&response), sizeof(response)))
	{
		clearLastError();
		_lastError << "Failed communicating with server on " << _socketHandler;
		return false;
	}

	if (!validateHeader(response.header, RESPONSE_ACK))
		return false;  // error message updated within.
	return true;
}

bool CClientLogic::nack_CRC_valid()
{
	SRequestAbortCommunication request;
	SResponseGeneric response;

	request.header.payloadSize = sizeof(request.payload);
	strcpy_s(reinterpret_cast<char*>(request.payload.filename.name), FILE_NAME_SIZE, _fileToBeSent.fileName.c_str());

	if (!_socketHandler->sendReceive(reinterpret_cast<const uint8_t* const>(&request), sizeof(request),
		reinterpret_cast<uint8_t* const>(&response), sizeof(response)))
	{
		clearLastError();
		_lastError << "Failed communicating with server on " << _socketHandler;
		return false;
	}

	if (!validateHeader(response.header, RESPONSE_ACK))
		return false;  // error message updated within.
	return true;
}


/**
 * Invoke logic: request client list from server.
 */
bool CClientLogic::requestClientsList()
{
	SRequestClientsList request(_self.id);
	uint8_t* payload = nullptr;
	uint8_t* ptr = nullptr;
	size_t payloadSize = 0;
	size_t parsedBytes = 0;
	struct
	{
		SClientID   clientId;
		SClientName clientName;
	}client;

	if (!receiveUnknownPayload(reinterpret_cast<uint8_t*>(&request), sizeof(request), RESPONSE_USERS, payload, payloadSize))
		return false;  // description was set within.

	if (payloadSize == 0)
	{
		delete[] payload;
		clearLastError();
		_lastError << "Server has no users registered. Empty Clients list.";
		return false;
	}
	if (payloadSize % sizeof(client) != 0)
	{
		delete[] payload;
		clearLastError();
		_lastError << "Clients list received is corrupted! (Invalid size).";
		return false;
	}
	ptr = payload;
	_clients.clear();
	while (parsedBytes < payloadSize)
	{
		memcpy(&client, ptr, sizeof(client));
		ptr += sizeof(client);
		parsedBytes += sizeof(client);
		client.clientName.name[sizeof(client.clientName.name) - 1] = '\0'; // just in case..
		_clients.push_back({ client.clientId, reinterpret_cast<char*>(client.clientName.name) });
	}
	delete[] payload;
	return true;
}


std::string CClientLogic::readInputFromFile(const std::string filename, int lineNumber)
{
	if (!_fileHandler->open(filename))
	{
		clearLastError();
		_lastError << "Couldn't open " << filename;
		throw std::runtime_error("File not found");
	}
	std::string username;
	for (int i = 1; i <= lineNumber; ++i)
	{
		!_fileHandler->readLine(username);
	}
	return username;
}

void CClientLogic::getPrivateKeyfromKeyFile(const std::string filepath, std::string& privKey)
{
	if (!_fileHandler->open(filepath))
	{
		clearLastError();
		_lastError << "Couldn't open " << filepath;
		return;
	}
	while (_fileHandler->readLine(privKey))
	{
		clearLastError();
		_lastError << "Couldn't read client's private key from " << filepath;
		return;
	}
	if (privKey.empty())
	{
		clearLastError();
		_lastError << "Couldn't read client's private key from " << filepath;
		return;
	}
	_fileHandler->close();
}

bool CClientLogic::retry()
{
	while (_fileToBeSent.shouldResend && _fileToBeSent.retryAttempts <= MAX_RETRIES)
		this->resendFile();

	return !_fileToBeSent.shouldResend;
}

bool CClientLogic::compareCRC(size_t serverChecksum)
{
	std::stringstream sstream(_fileToBeSent.checksum);
	size_t clientCRC;
	sstream >> clientCRC;
	return clientCRC == serverChecksum;
}