import config

config = config.Config()


class File:
    """ File entry """

    def __init__(self, cid, fname, pname, verified):
        self.ID = bytes.fromhex(cid)  # UID, 16 bytes.
        self.FileName = fname  # File name, 255 characters.
        self.PathName = pname  # Path name, 255 characters.
        self.Verified = verified  # bool

    def validate_file(self):
        """ Validating File attributes """
        if not self.ID or len(self.ID) != config.client_id_size:
            return False
        if not self.FileName or len(self.FileName) >= config.file_name_size:
            return False
        if not self.PathName or len(self.PathName) != config.path_name_size:
            return False
        if not isinstance(self.Verified, bool):
            return False
        return True
