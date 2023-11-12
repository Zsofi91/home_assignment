import struct
import config
import logging

config = config.Config()
logging.basicConfig(format='[%(levelname)s - %(asctime)s]: %(message)s', level=logging.INFO, datefmt='%H:%M:%S')


class RequestHeader:
    def __init__(self):
        self.clientID = b""
        self.version = config.def_val
        self.code = config.def_val
        self.payload_size = config.def_val
        self.size = config.client_id_size + config.header_size

    def unpack(self, data):
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
        try:
            return struct.pack("<BHL", self.version, self.code, self.payload_size)
        except:
            return b""


class RegistrationRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.name = b""

    def unpack(self, data):
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
        if not self.header.unpack(data):
            return False
        try:
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
        self.content_size = config.def_val
        self.file_name = b""
        self.message_content = b""

    def unpack(self, conn, data):
        # TODO: double check this code
        packet_size = len(data)
        if not self.header.unpack(data):
            return False
        try:
            content_size = data[self.header.size:self.header.size + config.content_size]
            self.content_size = struct.unpack(f"<{config.content_size}s", content_size)[0]
            file_name = data[self.header.size + config.content_size:self.header.size + config.content_size +
                                                               config.file_name_size]
            self.file_name = struct.unpack(f"<{config.file_name_size}s", file_name)[0]
            offset = self.header.size + config.content_size + config.file_name_size
            bytes_to_read = packet_size - offset
            if bytes_to_read > self.content_size:
                bytes_to_read = self.content_size
            self.message_content = struct.unpack(f"<{bytes_to_read}s", data[offset:offset + bytes_to_read])[0]
            while bytes_to_read < self.content_size:
                data = conn.recv(packet_size),
                data_size = len(data)
                if (self.content_size - bytes_to_read) < data_size:
                    data_size = self.content_size - bytes_to_read
                self.content_size += struct.unpack(f"<{data_size}s", data[:data_size])[0]
                bytes_to_read += data_size
            return True
        except:
            self.content_size = config.def_val
            self.file_name = b""
            self.message_content = b""
            return False


class SendingFileResponse:
    def __init__(self):
        self.header = ResponseHeader(config.file_received_ok_with_crc)
        self.clientID = b""
        self.content_size = config.def_val
        self.file_name = b""
        self.cksum = b""

    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{config.client_id_size}s", self.clientID)
            data += struct.pack(f"<{config.content_size}s", self.content_size)
            data += struct.pack(f"<{config.cksum_size}s", self.cksum)
            return data
        except:
            return b""


class ValidCRCRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.file_name = b""

    def unpack(self, data):
        if not self.header.unpack(data):
            return False
        try:
            file_name_data = data[self.header.size:self.header.size + config.file_name_size]
            self.file_name = str(struct.unpack(f"<{config.file_name_size}s", file_name_data)[0].partition(b'\0')[0].
                                 decode('utf-8'))
            return True
        except:
            self.file_name = b""
            return False


class CRCResponse:
    def __init__(self):
        self.header = ResponseHeader(config.confirm_crc_msg_received)
        self.clientID = b""

    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{config.client_id_size}s", self.clientID)
            return data
        except:
            return b""


class InvalidCRCRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.file_name = b""

    def unpack(self, data):
        if not self.header.unpack(data):
            return False
        try:
            file_name_data = data[self.header.size:self.header.size + config.file_name_size]
            self.file_name = str(struct.unpack(f"<{config.file_name_size}s", file_name_data)[0].partition(b'\0')[0].
                                 decode('utf-8'))
            return True
        except:
            self.file_name = b""
            return False
