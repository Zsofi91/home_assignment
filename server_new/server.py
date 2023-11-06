import logging
import threading
import socket
import uuid

import database
import helpers
import protocol
from datetime import datetime
import config

config = config.Config()

logging.basicConfig(format='[%(levelname)s - %(asctime)s]: %(message)s', level=logging.INFO, datefmt='%H:%M:%S')


class Server:
    DATABASE = 'defensive.db'
    PACKET_SIZE = 1024

    def __init__(self, host, port):
        """ Initializing server """
        self.host = host
        self.port = port
        self.database = database.Database(Server.DATABASE)
        self.request_handle = {
            config.registration_request: self.handle_registration_request,
            config.sending_public_key: self.sending_public_key,
            config.reconnection_request: self.handle_reconnection_request,
            config.sending_file: self.sending_file,
            config.valid_crc: self.sending_valid_crc_request,
            config.non_valid_crc: self.invalid_crc_resending_request,
            config.non_valid_crc_fourth_time: self.invalid_crc_resending_last_time
        }

    def read(self, conn):
        """ read data from client and parse it"""
        logging.info("A client has connected.")
        data = conn.recv(Server.PACKET_SIZE)
        if data:
            request_header = protocol.RequestHeader()
            success = False
            if not request_header.unpack(data):
                logging.error("Failed to parse request header!")
            else:
                if request_header.code in self.request_handle.keys():
                    success = self.request_handle[request_header.code](conn, data)  # invoke corresponding handle.
            if not success:  # returning error depending on failure
                if request_header.code == config.registration_request:
                    response_header = protocol.ResponseHeader(config.registration_failed)
                    self.write(conn, response_header.pack())
                if request_header.code == config.reconnection_request:
                    response_header = protocol.ResponseHeader(config.reconnection_request_rejected)
                    self.write(conn, response_header.pack())
                    # register client as it would be a new client
                    registered = self.handle_registration_request(conn, data)
                    if not registered:
                        response_header = protocol.ResponseHeader(config.registration_failed)
                        self.write(conn, response_header.pack())
                else:
                    # returning general error
                    response_header = protocol.ResponseHeader(config.general_error_response)
                    self.write(conn, response_header.pack())
                conn.close()

    def write(self, conn, data):
        """ Send a response to client"""
        size = len(data)
        sent = 0
        while sent < size:
            leftover = size - sent
            if leftover > Server.PACKET_SIZE:
                leftover = Server.PACKET_SIZE
            to_send = data[sent:sent + leftover]
            if len(to_send) < Server.PACKET_SIZE:
                to_send += bytearray(Server.PACKET_SIZE - len(to_send))
            try:
                conn.send(to_send)
                sent += len(to_send)
            except:
                logging.error("Failed to send response to " + conn)
                return False
        logging.info("Response sent successfully.")
        return True

    def start(self):
        """ Start listening for connections in infinite loop. """
        self.database.initialize()
        try:
            sock = socket.socket()
            sock.bind((self.host, self.port))
            sock.listen()
        except Exception as e:
            logging.error(f"error in creating socket due to: {e}")
            return False
        logging.info(f"Server is listening for connections on port {self.port}..")
        while True:
            try:
                client_conn, client_address = sock.accept()
                client_handler = threading.Thread(target=self.read, args=(client_conn,))
                client_handler.start()
            except Exception as e:
                logging.exception(f"Server main loop exception: {e}")

    def handle_registration_request(self, conn, data):
        """ Register a new user. """
        request = protocol.RegistrationRequest()
        response = protocol.RegistrationResponse()
        if not request.unpack(data):
            logging.error("Registration Request: Failed parsing request.")
            return False
        try:
            if not request.name.isalnum():
                logging.info(f"Registration Request: Invalid requested username ({request.name}))")
                return False
            if self.database.client_username_exists(request.name):
                logging.info(f"Registration Request: Username ({request.name}) already exists.")
                return False
        except:
            logging.error("Registration Request: Failed to connect to database.")
            return False
        client = database.Client(uuid.uuid4().hex, request.name)
        if not self.database.store_client(client):
            logging.error(f"Registration Request: Failed to store client {request.name}.")
            return False
        logging.info(f"Successfully registered client {request.name}.")
        response.clientID = client.ID
        response.header.payload_size = config.client_id_size
        return self.write(conn, response.pack())

    def sending_public_key(self, conn, data):
        """ Receive public key from a new user. """
        request = protocol.SendingPublicKeyRequest()
        response = protocol.SendingPublicKeyResponse()
        if not request.unpack(data):
            logging.error("Sending Public Key Request: Failed parsing request.")
            return False
        try:
            if not self.database.client_username_exists(request.name):
                logging.info(f"Sending Public Key Request:: Username ({request.name}) already exists.")
                return False
        except:
            logging.error("Sending Public Key Request: Failed to connect to database.")
            return False
        #  update the relevant client with the public key
        try:
            if not self.database.update_public_key(request.name):
                logging.error("Sending Public Key Request: Failed to update public key in database")
                return False
        except:
            logging.error("Sending Public Key Request: Failed to connect to database.")
            return False
        # generate aes key
        aes_key = helpers.generate_aes_key()
        # save aes key to database for relevant client
        try:
            if not self.database.update_aes_key(request.name):
                logging.error("Sending Public Key Request: Failed to update aes key in database")
                return False
        except Exception as e:
            logging.error(f"Sending Public Key Request: Failed to connect to database due to: {e}.")
            return False
        # encrypt aes key
        encrypted_aes_key = helpers.encrypt_aes_key(aes_key, request.public_key)
        # retrieving client_id from database
        try:
            client_id = self.database.get_client_id(request.name)
            logging.info(f"Sending Public Key Request: Get client_id for client: {request.name}")
        except Exception as e:
            logging.error(f"Sending Public Key Request: Failed to get client_id due to: {e}.")
            return False
        response.clientID = client_id
        response.aes_key = encrypted_aes_key
        response.header.payload_size = config.client_id_size
        return self.write(conn, response.pack())

    def handle_reconnection_request(self, conn, data):
        """ Receive reconnection request from a new user. """
        request = protocol.ReconnectionRequest()
        response = protocol.ReconnectionResponse()
        if not request.unpack(data):
            logging.error("Reconnection Request: Failed parsing request.")
            return False
        try:
            if not self.database.client_username_exists(request.name):
                logging.info(f"Reconnection Request:: Username ({request.name}) doesn't exist.")
                return False
        except:
            logging.error("Reconnection Request: Failed to connect to database.")
            return False
        # update LastSeen for client
        now = datetime.now()
        try:
            self.database.update_last_seen(request.name, now)
            logging.info(f"Reconnection Request: updated LastSeen for client: {request.name}")
        except:
            logging.error(f"Reconnection Request: Failed to update LastSeen for client: {request.name}.")
        # retrieve client_id, public_key and aes_key from database
        try:
            client_id = self.database.get_client_id(request.name)
            aes_key = self.database.get_aes_key(request.name)
            public_key = self.database.get_public_key(request.name)
        except Exception as e:
            logging.error(f"Reconnection Request: Failed to retrieve client_id and aes_key due to: {e}")
            return False
        # encrypt aes_key
        encrypted_aes_key = helpers.encrypt_aes_key(aes_key, public_key)
        response.clientID = client_id
        response.aes_key = encrypted_aes_key
        response.header.payload_size = config.client_id_size
        return self.write(conn, response.pack())

    def sending_file(self, conn, data):
        """ receive a file from a client """
        request = protocol.SendingFileRequest()
        response = protocol.SendingFileResponse()

    # def handleMessageSendRequest(self, conn, data):
    #     """ store a message from one user to another """
    #     request = protocol.MessageSendRequest()
    #     response = protocol.MessageSentResponse()
    #     if not request.unpack(conn, data):
    #         logging.error("Send Message Request: Failed to parse request header!")
    #
    #     msg = database.Message(request.clientID,
    #                            request.header.clientID,
    #                            request.messageType,
    #                            request.content)
    #
    #     msgId = self.database.storeMessage(msg)
    #     if not msgId:
    #         logging.error("Send Message Request: Failed to store msg.")
    #         return False
    #
    #     response.header.payloadSize = protocol.CLIENT_ID_SIZE + protocol.MSG_ID_SIZE
    #     response.clientID = request.clientID
    #     response.messageID = msgId
    #     logging.info(f"Message from clientID ({request.header.clientID}) successfully stored.")
    #     return self.write(conn, response.pack())
    #
    # def handlePendingMessagesRequest(self, conn, data):
    #     """ respond with pending messages """
    #     request = protocol.RequestHeader()
    #     response = protocol.ResponseHeader(protocol.EResponseCode.RESPONSE_PENDING_MSG.value)
    #     if not request.unpack(data):
    #         logging.error("Pending messages request: Failed to parse request header!")
    #     try:
    #         if not self.database.clientIdExists(request.clientID):
    #             logging.info(f"clientID ({request.clientID}) does not exists!")
    #             return False
    #     except:
    #         logging.error("Pending messages request: Failed to connect to database.")
    #         return False
    #
    #     payload = b""
    #     messages = self.database.getPendingMessages(request.clientID)
    #     ids = []
    #     for msg in messages:  # id, from, type, content
    #         pending = protocol.PendingMessage()
    #         pending.messageID = int(msg[0])
    #         pending.messageClientID = msg[1]
    #         pending.messageType = int(msg[2])
    #         pending.content = msg[3]
    #         pending.messageSize = len(msg[3])
    #         ids += [pending.messageID]
    #         payload += pending.pack()
    #     response.payloadSize = len(payload)
    #     logging.info(f"Pending messages to clientID ({request.clientID}) successfully extracted.")
    #     if self.write(conn, response.pack() + payload):
    #         for msg_id in ids:
    #             self.database.removeMessage(msg_id)
    #         return True
    #     return False