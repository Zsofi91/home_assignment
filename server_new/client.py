import config

config = config.Config()


class Client:
    """ Client entry """

    def __init__(self, cid, cname, last_seen=None, public_key=None, aes_key=None):
        self.ID = bytes.fromhex(cid)  # UID, 16 bytes.
        self.Name = cname  # Client's name, 255 characters.
        self.PublicKey = public_key  # Client's public key, 160 bytes.
        self.LastSeen = last_seen  # date & time of client's last request.
        self.AESKey = aes_key  # 128 bits

    def validate_client(self):
        """ Validating Client attributes """
        if not self.ID or len(self.ID) != config.client_id_size:
            return False
        if not self.Name or len(self.Name) >= config.name_size:
            return False
        if not self.PublicKey or len(self.PublicKey) != config.public_key_size:
            return False
        if not self.LastSeen:
            return False
        if not self.AESKey or len(self.AESKey) != config.aes_key_size:
            return False
        return True
