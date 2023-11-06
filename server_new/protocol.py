import struct
import config
import logging

config = config.Config()
logging.basicConfig(format='[%(levelname)s - %(asctime)s]: %(message)s', level=logging.INFO, datefmt='%H:%M:%S')

MSG_ID_SIZE = 4
MSG_TYPE_MAX = 0xFF
MSG_ID_MAX = 0xFFFFFFFF


class RequestHeader:
    def __init__(self):
        self.clientID = b""
        self.version = config.def_val
        self.code = config.def_val
        self.payload_size = config.def_val
        self.size = config.client_id_size + config.header_size

    def unpack(self, data):
        """ Little Endian unpack Request Header """
        try:
            self.clientID = struct.unpack(f"<{config.client_id_size}s", data[:config.client_id_size])[0]
            header_data = data[config.client_id_size:config.client_id_size + config.header_size]
            self.version, self.code, self.payload_size = struct.unpack("<BHL", header_data)
            return True
        except Exception as e:
            logging.error(f"Unpacking request header failed due to: {e}")
            self.__init__()  # reset values
            return False


class ResponseHeader:
    def __init__(self, code):
        self.version = config.server_version
        self.code = code
        self.payload_size = config.def_val
        self.size = config.client_id_size + config.header_size

    def pack(self):
        """ Little Endian pack Response Header """
        try:
            return struct.pack("<BHL", self.version, self.code, self.payload_size)
        except:
            return b""


class RegistrationRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.name = b""

    def unpack(self, data):
        """ Little Endian unpack Request Header and Registration data """
        if not self.header.unpack(data):
            return False
        try:
            name_data = data[self.header.size:self.header.size + config.name_size]
            self.name = str(struct.unpack(f"<{config.name_size}s", name_data)[0].partition(b'\0')[0].decode('utf-8'))
            return True
        except:
            self.name = b""
            return False


class RegistrationResponse:
    def __init__(self):
        self.header = ResponseHeader(config.successful_registration)
        self.clientID = b""

    def pack(self):
        """ Little Endian pack Response Header and client ID """
        try:
            data = self.header.pack()
            data += struct.pack(f"<{config.client_id_size}s", self.clientID)
            return data
        except:
            return b""


class SendingPublicKeyRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.name = b""
        self.public_key = b""

    def unpack(self, data):
        """ Little Endian unpack Request Header and Registration data """
        if not self.header.unpack(data):
            return False
        try:
            # trim the byte array after the nul terminating character.
            name_data = data[self.header.size:self.header.size + config.name_size]
            self.name = str(struct.unpack(f"<{config.name_size}s", name_data)[0].partition(b'\0')[0].decode('utf-8'))
            public_key_data = data[self.header.size + config.name_size:self.header.size + config.name_size +
                                                               config.public_key_size]
            self.public_key = struct.unpack(f"<{config.public_key_size}s", public_key_data)[0]
            return True
        except:
            self.name = b""
            self.public_key = b""
            return False


class SendingPublicKeyResponse:
    def __init__(self):
        self.header = ResponseHeader(config.exchanging_keys)
        self.clientID = b""
        self.aes_key = b""

    def pack(self):
        """ Little Endian pack Response Header and client ID """
        try:
            data = self.header.pack()
            data += struct.pack(f"<{config.client_id_size}s", self.clientID)
            data += struct.pack(f"<{config.aes_key_size}s", self.aes_key)
            return data
        except:
            return b""


class ReconnectionRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.name = b""

    def unpack(self, data):
        """ Little Endian unpack Request Header and Registration data """
        if not self.header.unpack(data):
            return False
        try:
            name_data = data[self.header.size:self.header.size + config.name_size]
            self.name = str(struct.unpack(f"<{config.name_size}s", name_data)[0].partition(b'\0')[0].decode('utf-8'))
            return True
        except:
            self.name = b""
            return False


class ReconnectionResponse:
    def __init__(self):
        self.header = ResponseHeader(config.confirm_reconnect_request_send_aes_encrypted)
        self.clientID = b""
        self.aes_key = b""

    def pack(self):
        """ Little Endian pack Response Header and client ID """
        try:
            data = self.header.pack()
            data += struct.pack(f"<{config.client_id_size}s", self.clientID)
            data += struct.pack(f"<{config.aes_key_size}s", self.aes_key)
            return data
        except:
            return b""


class SendingFileRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.content_size = b""
        self.file_name = b""
        self.message_content = b""

    def unpack(self, data):
        """ Little Endian unpack Request Header and Registration data """
        packet_size = len(data)
        if not self.header.unpack(data):
            return False
        try:
            # trim the byte array after the nul terminating character.
            content_size = data[self.header.size:self.header.size + config.content_size]
            self.content_size = str(struct.unpack(f"<{config.content_size}s", content_size)[0].partition(b'\0')[0].
                                    decode('utf-8'))
            # TODO: double check this code
            file_name = data[self.header.size + config.content_size:self.header.size + config.content_size +
                                                               config.file_name_size]
            self.file_name = struct.unpack(f"<{config.file_name_size}s", file_name)[0]
            # TODO: understand message_content
            self.message_content = ""
            return True
        except:
            self.content_size = b""
            self.file_name = b""
            self.message_content = b""
            return False


class SendingFileResponse:
    pass


#

# class MessageSendRequest:
#     def __init__(self):
#         self.header = RequestHeader()
#         self.clientID = b""
#         self.messageType = DEF_VAL
#         self.contentSize = DEF_VAL
#         self.content = b""
#
#     def unpack(self, conn, data):
#         """ Little Endian unpack Request Header and message data """
#         packetSize = len(data)
#         if not self.header.unpack(data):
#             return False
#         try:
#             clientID = data[self.header.SIZE:self.header.SIZE + CLIENT_ID_SIZE]
#             self.clientID = struct.unpack(f"<{CLIENT_ID_SIZE}s", clientID)[0]
#             offset = self.header.SIZE + CLIENT_ID_SIZE
#             self.messageType, self.contentSize = struct.unpack("<BL", data[offset:offset + 5])
#             offset = self.header.SIZE + CLIENT_ID_SIZE + 5
#             bytesRead = packetSize - offset
#             if bytesRead > self.contentSize:
#                 bytesRead = self.contentSize
#             self.content = struct.unpack(f"<{bytesRead}s", data[offset:offset + bytesRead])[0]
#             while bytesRead < self.contentSize:
#                 data = conn.recv(packetSize)  # reuse first size of data.
#                 dataSize = len(data)
#                 if (self.contentSize - bytesRead) < dataSize:
#                     dataSize = self.contentSize - bytesRead
#                 self.content += struct.unpack(f"<{dataSize}s", data[:dataSize])[0]
#                 bytesRead += dataSize
#             return True
#         except:
#             self.clientID = b""
#             self.messageType = DEF_VAL
#             self.contentSize = DEF_VAL
#             self.content = b""
#             return False
# #
#
# class MessageSentResponse:
#     def __init__(self):
#         self.header = ResponseHeader(EResponseCode.RESPONSE_MSG_SENT.value)
#         self.clientID = b""
#         self.messageID = b""
#
#     def pack(self):
#         """ Little Endian pack Response Header and client ID """
#         try:
#             data = self.header.pack()
#             data += struct.pack(f"<{CLIENT_ID_SIZE}sL", self.clientID, self.messageID)
#             return data
#         except:
#             return b""
#
#
# class PendingMessage:
#     def __init__(self):
#         self.messageClientID = b""
#         self.messageID = 0
#         self.messageType = 0
#         self.messageSize = 0
#         self.content = b""
#
#     def pack(self):
#         try:
#             """ Little Endian pack Response Header and pending message header """
#             data = struct.pack(f"<{CLIENT_ID_SIZE}s", self.messageClientID)
#             data += struct.pack("<LBL", self.messageID, self.messageType, self.messageSize)
#             data += struct.pack(f"<{self.messageSize}s", self.content)
#             return data
#         except:
#             return b""


