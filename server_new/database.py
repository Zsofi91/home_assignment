import logging
import sqlite3
import config
from client import Client
from message import Message

config = config.Config()


class Database:
    CLIENTS = 'clients'
    FILES = 'files'

    def __init__(self, name):
        self.name = name

    def connect(self):
        conn = sqlite3.connect(self.name)
        conn.text_factory = bytes
        return conn

    def execute_script(self, script):
        conn = self.connect()
        try:
            conn.executescript(script)
            conn.commit()
        except Exception as e:
            logging.exception(f"Couldn't create Clients and Files tables due to: {e}")
        conn.close()

    def execute(self, query, args, commit=False, get_last_row=False):
        """ Given a query and args, execute query, and return the results. """
        results = None
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(query, args)
            if commit:
                conn.commit()
                results = True
            else:
                results = cur.fetchall()
            # if get_last_row:
            #     results = cur.lastrowid
        except Exception as e:
            logging.exception(f'database execute: {e}')
        conn.close()  # commit is not required.
        return results

    def initialize(self):
        # Try to create Clients table
        self.execute_script(f"""
            CREATE TABLE IF NOT EXISTS {Database.CLIENTS}(
              ID BLOB(16) PRIMARY KEY NOT NULL,
              Name CHAR(255) NOT NULL,
              PublicKey BLOB(20) NOT NULL,
              LastSeen DATETIME,
              AESKey BLOB(16) NOT NULL              
            );
            """)

        # Try to create Files table
        self.execute_script(f"""
            CREATE TABLE IF NOT EXISTS {Database.FILES}(
              ID BLOB(16) PRIMARY KEY NOT NULL,
              FileName CHAR(255) NOT NULL,
              PathName CHAR(255) NOT NULL,
              Verified BOOLEAN NOT NULL DEFAULT 0
            );
            """)

    def client_username_exists(self, username):
        """ Check whether a username already exists within database """
        results = self.execute(f"SELECT * FROM {Database.CLIENTS} WHERE Name = ?", [username])
        if not results:
            return False
        return len(results) > 0

    def store_client(self, client):
        """ Store a client into database """
        if not type(client) is Client or not client.validate():
            return False
        return self.execute(f"INSERT INTO {Database.CLIENTS} VALUES (?, ?, ?, ?, ?)",
                            [client.ID, client.Name, client.PublicKey, client.LastSeen, client.AESKey], True)

    def update_public_key(self, client_id):
        """ Set public key given client id """
        return self.execute(f"UPDATE {Database.CLIENTS} SET PublicKey = ? WHERE ID = ?", [client_id], True)

    def update_aes_key(self, client_id):
        """ Set aes key given client id"""
        return self.execute(f"UPDATE {Database.CLIENTS} SET AESKey = ? WHERE ID = ?", [client_id], True)

    def update_last_seen(self, client_id, time):
        """ Set LastSeen given client id """
        return self.execute(f"UPDATE {Database.CLIENTS} SET LastSeen = ? WHERE ID = ?", [time, client_id], True)

    def get_client_name(self, client_id):
        """ Get client_name given client id """
        return self.execute(f"SELECT Name FROM {Database.CLIENTS} WHERE ID = ?", [client_id])

    def get_aes_key(self, client_id):
        """ Get aes_key given client id """
        return self.execute(f"SELECT AESKey FROM {Database.CLIENTS} WHERE ID = ?", [client_id])

    def get_public_key(self, client_id):
        """ Get public_key given client id """
        return self.execute(f"SELECT PublicKey FROM {Database.CLIENTS} WHERE ID = ?", [client_id])

    def store_file_name(self, file):
        """ Store a file name with path into database """
        results = self.execute(
            f"INSERT INTO {Database.MESSAGES}(ToClient, FromClient, Type, Content) VALUES (?, ?, ?, ?)",
            [msg.ToClient, msg.FromClient, msg.Type, msg.Content], True, True)
        return results

    #
    # def removeMessage(self, msg_id):
    #     """ remove a message by id from database """
    #     return self.execute(f"DELETE FROM {Database.MESSAGES} WHERE ID = ?", [msg_id], True)
    #
    #
    # def getClientsList(self):
    #     """ query for all clients """
    #     return self.execute(f"SELECT ID, Name FROM {Database.CLIENTS}", [])
    #
    #
    # def getPendingMessages(self, client_id):
    #     """ given a client id, return pending messages for that client. """
    #     return self.execute(f"SELECT ID, FromClient, Type, Content FROM {Database.MESSAGES} WHERE ToClient = ?",
    #                         [client_id])
