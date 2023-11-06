/**
 * MessageU Client
 * @file protocol.h
 * @brief Define protocol between client & server according to the requirements.
 * structs are aligned to 1 byte with the directive command pragma pack(push, 1).
 * @author Roman Koifman
 * https://github.com/Romansko/MessageU/blob/main/client/header/protocol.h
 */

#pragma once
#include <cstdint>

enum { DEF_VAL = 0 };  // Default value used to initialize protocol structures.

// Common types
typedef uint8_t  version_t;
typedef uint16_t code_t;
typedef uint8_t  messageType_t;
typedef uint32_t messageID_t;
typedef uint32_t csize_t;  // protocol's size type: Content's, payload's and message's size.

// Constants. All sizes are in BYTES.
constexpr version_t CLIENT_VERSION = 3;
constexpr size_t    CLIENT_ID_SIZE = 16;
constexpr size_t    CLIENT_NAME_SIZE = 255;
constexpr size_t    PUBLIC_KEY_SIZE = 160;  // defined in protocol. 1024 bits.
constexpr size_t    SYMMETRIC_KEY_SIZE = 16;   // defined in protocol.  128 bits.
constexpr size_t    REQUEST_OPTIONS = 5;
constexpr size_t    RESPONSE_OPTIONS = 6;

enum ERequestCode
{
	REQUEST_REGISTRATION = 1025,   // uuid ignored.
	REQUEST_PUBLIC_KEY_REGISTRATION = 1026,
	REQUEST_CLIENTS_LIST = 1001,   // payload invalid. payloadSize = 0.
	REQUEST_PUBLIC_KEY = 1002,
	REQUEST_SEND_MSG = 1003,
	REQUEST_PENDING_MSG = 1004    // payload invalid. payloadSize = 0.
};

enum EResponseCode
{
	RESPONSE_REGISTRATION = 2100,
	RESPONSE_USERS = 2001,
	RESPONSE_PUBLIC_KEY = 2002,
	RESPONSE_MSG_SENT = 2003,
	RESPONSE_PENDING_MSG = 2004,
	RESPONSE_ERROR = 2107    // payload invalid. payloadSize = 0.
};

enum EResponseErrorCodes
{
	REGISTRATION_RESPONSE_ERROR = 2101
	
};

enum EMessageType
{
	MSG_SYMMETRIC_KEY_REQUEST = 1,   // content invalid. contentSize = 0.
	MSG_SYMMETRIC_KEY_SEND = 2,   // content = symmetric key encrypted by destination client's public key.
	MSG_TEXT = 3,   // content = encrypted message by symmetric key.
	MSG_FILE = 4    // content = encrypted file by symmetric key.
};

#pragma pack(push, 1)

struct SClientID
{
	uint8_t uuid[CLIENT_ID_SIZE];
	SClientID() : uuid{ DEF_VAL } {}

	bool operator==(const SClientID& otherID) const {
		for (size_t i = 0; i < CLIENT_ID_SIZE; ++i)
			if (uuid[i] != otherID.uuid[i])
				return false;
		return true;
	}

	bool operator!=(const SClientID& otherID) const {
		return !(*this == otherID);
	}

};

struct SClientName
{
	uint8_t name[CLIENT_NAME_SIZE];  // DEF_VAL terminated.
	SClientName() : name{ '\0' } {}
};

struct SPublicKey
{
	uint8_t publicKey[PUBLIC_KEY_SIZE];
	SPublicKey() : publicKey{ DEF_VAL } {}
};

struct SSymmetricKey
{
	uint8_t symmetricKey[SYMMETRIC_KEY_SIZE];
	SSymmetricKey() : symmetricKey{ DEF_VAL } {}
};

struct SRequestHeader
{
	SClientID       clientId;
	const version_t version;
	const code_t    code;
	csize_t         payloadSize;
	SRequestHeader(const code_t reqCode) : version(CLIENT_VERSION), code(reqCode), payloadSize(DEF_VAL) {}
	SRequestHeader(const SClientID& id, const code_t reqCode) : clientId(id), version(CLIENT_VERSION), code(reqCode), payloadSize(DEF_VAL) {}
};

struct SResponseHeader
{
	version_t version;
	code_t    code;
	csize_t   payloadSize;
	SResponseHeader() : version(DEF_VAL), code(DEF_VAL), payloadSize(DEF_VAL) {}
};

struct SRequestRegistration
{
	SRequestHeader header;
	struct
	{
		SClientName Name;
		//SPublicKey  clientPublicKey;
	}payload;
	SRequestRegistration() : header(REQUEST_REGISTRATION) {}
};

struct SResponseRegistration
{
	SResponseHeader header;
	SClientID       payload;
};

struct SRequestClientsList
{
	SRequestHeader header;
	SRequestClientsList(const SClientID& id) : header(id, REQUEST_CLIENTS_LIST) {}
};

struct SResponseClientsList
{
	SResponseHeader header;
	/* variable { SClientID + SClientName } */
};

struct SRequestPublicKey
{
	SRequestHeader header;
	SClientID      payload;
	SRequestPublicKey(const SClientID& id) : header(id, REQUEST_PUBLIC_KEY) {}
};

struct SResponsePublicKey
{
	SResponseHeader header;
	struct
	{
		SClientID   clientId;
		SPublicKey  clientPublicKey;
	}payload;
};

struct SRequestSendMessage
{
	SRequestHeader header;
	struct SPayloadHeader
	{
		SClientID           clientId;   // destination client
		const messageType_t messageType;
		csize_t             contentSize;
		SPayloadHeader(const messageType_t type) : messageType(type), contentSize(DEF_VAL) {}
	}payloadHeader;
	SRequestSendMessage(const SClientID& id, const messageType_t type) : header(id, REQUEST_SEND_MSG), payloadHeader(type) {}
};

struct SResponseMessageSent
{
	SResponseHeader header;
	struct SPayload
	{
		SClientID   clientId;   // destination client
		messageID_t messageId;
		SPayload() : messageId(DEF_VAL) {}
	}payload;
};

struct SRequestMessages
{
	SRequestHeader header;
	SRequestMessages(const SClientID& id) : header(id, REQUEST_PENDING_MSG) {}
};


struct SPendingMessage
{
	SClientID     clientId;   // message's clientID.
	messageID_t   messageId;
	messageType_t messageType;
	csize_t       messageSize;
	/* Variable Size content */
	SPendingMessage() : messageId(DEF_VAL), messageType(DEF_VAL), messageSize(DEF_VAL) {}
};


#pragma pack(pop)
