class Config:
    def __init__(self):
        self.default_port = 1357
        self.server_version = 3

        self.def_val = 0
        self.client_id_size = 16
        self.header_size = 7  # Header size without clientID (version, code, payload size).

        self.name_size = 255
        self.public_key_size = 160
        self.content_size = 4
        self.aes_key_size = 128
        self.file_name_size = 255
        self.cksum_size = 4

        self.registration_request = 1025
        self.sending_public_key = 1026
        self.reconnection_request = 1027
        self.sending_file = 1028
        self.valid_crc = 1029
        self.non_valid_crc = 1030
        self.non_valid_crc_fourth_time = 1031

        self.successful_registration = 2100
        self.registration_failed = 2101
        self.exchanging_keys = 2102
        self.file_received_ok_with_crc = 2103
        self.confirm_reconnect_request_send_aes_encrypted = 2105

        self.reconnection_request_rejected = 2106
        self.general_error_response = 2107


        self.confirm_received_message = 2104



