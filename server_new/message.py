import config
from helpers import cksum
config = config.Config()


class Message:
    """ Message entry """

    def __init__(self, file_name, path_name):
        self.ID = 0  # 16 bytes.
        self.FileName = file_name  # 255 bytes.
        self.PathName = path_name  # 255 bytes.
        self.Verified = False  # boolean value

    def validate_message(self):
        """ Validate Message attributes """
        if not self.ID or len(self.ID) != config.msg_id_size:
            return False
        if not self.FileName or len(self.FileName) >= config.file_name_size:
            return False
        if not self.PathName or len(self.PathName) != config.path_name_size:
            return False
        check_sum = cksum("file_name")
        if check_sum != '':
            return False
        return True
