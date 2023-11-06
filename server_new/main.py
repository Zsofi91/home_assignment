import helpers
import server
import config

config = config.Config()

if __name__ == '__main__':
    port_info = "server_new/port.info"
    port = helpers.parse_port(port_info)
    if port is None:
        port = config.default_port
    svr = server.Server('', port)
    if not svr.start():
        helpers.stop_server(f"Server couldn't start")
