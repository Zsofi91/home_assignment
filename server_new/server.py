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
                    # TODO: register client as it would be a new client - only if it failed due to not registered yet
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
            except Exception as err:
                logging.error(f"Failed to send response to {conn} due to {err}")
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
        client = database.Client(uuid.uuid4().hex, request.name, str(datetime.now()))
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
                logging.info(f"Sending Public Key Request:: Username ({request.name}) doesn't exist.")
                return False
        except:
            logging.error("Sending Public Key Request: Failed to connect to database.")
            return False
        #  update the relevant client with the public key
        try:
            if not self.database.update_public_key(request.header.clientID):
                logging.error("Sending Public Key Request: Failed to update public key in database")
                return False
        except:
            logging.error("Sending Public Key Request: Failed to connect to database.")
            return False
        # generate aes key
        aes_key = helpers.generate_aes_key()
        try:
            # save aes key to database for relevant client
            if not self.database.update_aes_key(request.header.clientID):
                logging.error("Sending Public Key Request: Failed to update aes key in database")
                return False
        except Exception as e:
            logging.error(f"Sending Public Key Request: Failed to connect to database due to: {e}.")
            return False
        # encrypt aes key
        encrypted_aes_key = helpers.encrypt_aes_key(aes_key, request.public_key)
        response.clientID = request.header.clientID
        response.aes_key = encrypted_aes_key
        response.header.payload_size = config.client_id_size + config.aes_key_size
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
            self.database.update_last_seen(request.header.clientID, now)
            logging.info(f"Reconnection Request: updated LastSeen for client: {request.name}")
        except:
            logging.error(f"Reconnection Request: Failed to update LastSeen for client: {request.name}.")
        try:
            # retrieve public_key and aes_key from db
            aes_key = self.database.get_aes_key(request.header.clientID)
            public_key = self.database.get_public_key(request.header.clientID)
        except Exception as e:
            logging.error(f"Reconnection Request: Failed to retrieve client_id and aes_key due to: {e}")
            return False
        # encrypt aes_key
        encrypted_aes_key = helpers.encrypt_aes_key(aes_key, public_key)
        response.clientID = request.header.clientID
        response.aes_key = encrypted_aes_key
        response.header.payload_size = config.client_id_size + config.aes_key_size
        return self.write(conn, response.pack())

    def sending_file(self, conn, data):
        """ receive a file from a client """
        request = protocol.SendingFileRequest()
        response = protocol.SendingFileResponse()
        if not request.unpack(conn, data):
            logging.error("Send File Request: Failed to parse request header!")
        try:
            # decrypt message content
            file_content = request.message_content
            client_id = request.header.clientID
            aes_key = self.database.get_aes_key(client_id)
            decrypted_msg_content = helpers.decrypt_file_content(file_content, aes_key)
            # save file to RAM
            file_path = helpers.save_to_ram(decrypted_msg_content, request.file_name)
            # calc cksum
            cksum = helpers.cksum(decrypted_msg_content)
            try:
                # store file details into db
                verified = False
                file_details = self.database.FILES(client_id, request.file_name, file_path, verified)
                self.database.file_details(file_details)
            except Exception as err:
                logging.error(f"Send File Request: Failed to store file details due to: {err}.")
                return False

            # update LastSeen for client
            now = datetime.now()
            try:
                self.database.update_last_seen(request.header.clientID, now)
                logging.info(f"Send File Request: updated LastSeen for client")
            except:
                logging.error(f"Send File Request: Failed to update LastSeen for client.")
            response.clientID = client_id
            response.content_size = request.content_size
            response.file_name = request.file_name
            response.cksum = cksum
            response.header.payload_size = config.client_id_size
            return self.write(conn, response.pack())
        except Exception as err:
            logging.error(f"Send File Request: Failed due to: {err}.")
            return False

    def sending_valid_crc_request(self, conn, data):
        """ Receive valid crc request. """
        request = protocol.ValidCRCRequest()
        response = protocol.CRCResponse()
        if not request.unpack(data):
            logging.error("Valid CRC Request: Failed parsing request.")
            return False
        # update LastSeen and verified CRC columns for client
        now = datetime.now()
        try:
            self.database.update_last_seen(request.header.clientID, now)
            self.database.update_verified_true(request.header.clientID)
            logging.info(f"Valid CRC Request: updated LastSeen and Verified to True for client.")
        except:
            logging.error(f"Valid CRC Request: Failed to update db for client.")
        response.clientID = request.header.clientID
        response.header.payload_size = config.client_id_size
        return self.write(conn, response.pack())

    def invalid_crc_resending_request(self, conn, data):
        """ Receive invalid crc request for the 4th time. """
        request = protocol.InvalidCRCRequest()
        response = protocol.CRCResponse()
        if not request.unpack(data):
            logging.error("Invalid CRC Request: Failed parsing request.")
            return False
        # update LastSeen column for client
        now = datetime.now()
        try:
            self.database.update_last_seen(request.header.clientID, now)
            logging.info(f"Invalid CRC Request: updated LastSeen for client.")
        except:
            logging.error(f"Invalid CRC Request: Failed to update db for client.")
        response.clientID = request.header.clientID
        response.header.payload_size = config.client_id_size
        return self.write(conn, response.pack())



