#author:    test
import gevent
from gevent import monkey

monkey.patch_all()
import logging
import socket
import select
import time
import json
import os
import requests
import configparser
from logging.config import dictConfig

from pymodbus.client.sync import ModbusTcpClient, ModbusSerialClient
from pymodbus.exceptions import ConnectionException, ModbusIOException
from pymodbus.pdu import ExceptionResponse

"""
command define: 
SET:
    send: "cmd:set:<address>:<value>
    recv: "cmd:set:<address>:<value>:<success/failed>

    specially:
        address == 0, means that client try to set the `max_speed`
GET:
    send: "cmd:get:<address>
    recv: "cmd:get:<address>:<value>
KEEP ALIVE: loop: <10s> * 3 times
    send: "cmd:keepalive:req"
    recv: "cmd:keepalive:rsp"

UPDATE CONFIG:
    send: "cmd:set_config:<target>:<value>
    recv: "cmd:set_config:<target>:<value>
"""

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.cfg")
TCP_SERVER_PORT = 10010
POLL_TIMEOUT = 3000  # ms
READ_ONLY = (select.POLLIN | select.POLLPRI | select.POLLHUP | select.POLLERR)
READ_WRITE = (READ_ONLY | select.POLLOUT)

logging_config = dict(
    version=1,
    formatters={
        'f': {'format': '[%(levelname)s] %(asctime)s %(name)s [%(lineno)d] %(message)s'}
    },
    handlers={
        'h': {'class': 'logging.StreamHandler', 'formatter': 'f', 'level': logging.DEBUG}
    },
    root={'handlers': ['h'], 'level': logging.DEBUG}
)
dictConfig(logging_config)
logger = logging.getLogger('Inverter')

conf = configparser.ConfigParser()
conf.read(CONFIG_FILE)


def get_bit(word, bit):
    return (word >> bit) & 0x01


def set_config_max_speed(speed):
    conf['GLOBAL'] = {"max_speed": speed}
    with open(CONFIG_FILE, 'w') as c:
        conf.write(c)


def get_config_max_speed():
    if "GLOBAL" not in conf or "max_speed" not in conf["GLOBAL"]:
        set_config_max_speed(1024)
        return 1024
    return conf["GLOBAL"]["max_speed"]


def gen_modbus_client():
    if "CONNECT" not in conf or 'method' not in conf["CONNECT"]:
        return None
    connect_conf = conf["CONNECT"]

    if "method" in connect_conf and connect_conf['method'] == "rtu":
        return ModbusSerialClient(**dict(connect_conf))
    else:
       return ModbusTcpClient(host=os.getenv("INVERTER_HOST", connect_conf['host']))


def gen_tcp_server(port):
    if port < 0 or port > 65535:
        return False
    _s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _s.bind(('0.0.0.0', port))
    _s.listen(5)
    return _s


def cmd_server():
    tcp_poller = select.poll()
    server = gen_tcp_server(TCP_SERVER_PORT)
    if not server:
        return

    logger.info("TCP Server listen on: 0.0.0.0:%d", TCP_SERVER_PORT)
    tcp_poller.register(server, READ_ONLY)
    fd_to_socket = {server.fileno(): server}

    modbus_client = gen_modbus_client()

    keepalive = 0

    while True:
        events = tcp_poller.poll(POLL_TIMEOUT)
        for fd, flag in events:
            s = fd_to_socket[fd]

            if flag & select.POLLHUP:
                try:
                    _client_name = s.getpeername()
                    logger.info("Client %s:%d Closed(HUP)", _client_name[0], _client_name[1])
                except OSError as e:
                    logger.error(e)
                    logger.info("Client Closed(HUP)")

                tcp_poller.unregister(s)
                s.close()
            elif flag & select.POLLERR:
                logger.error("Exception on %s:%d", s.getpeername()[0], s.getpeername()[1])
                tcp_poller.unregister(s)
                s.close()
            elif flag & (select.POLLPRI | select.POLLIN):
                if s is server:
                    connection, client_address = s.accept()
                    logger.info("Connection from: %s:%d", client_address[0], client_address[1])
                    connection.setblocking(False)
                    fd_to_socket[connection.fileno()] = connection
                    tcp_poller.register(connection, READ_ONLY)
                else:
                    try:
                        data = s.recv(1024)
                    except Exception as e:
                        tcp_poller.unregister(s)
                        logger.error(e)
                        continue

                    if not data:
                        try:
                            peer_address = s.getpeername()
                            logger.info("Client %s:%d closed", peer_address[0], peer_address[1])
                        except OSError as e:
                            logger.error(e)

                        tcp_poller.unregister(s)
                        s.close()
                        modbus_client.close()
                    else:
                        logger.info("Received: %s", data.decode('utf-8'))
                        try:
                            cmd_list = data.decode('utf-8').split(":")

                            if len(cmd_list) < 3:
                                s.send(data)
                                logger.error('Invalid msg: %s', data)
                            elif cmd_list[0] == 'cmd':
                                if cmd_list[1] == 'get':
                                    modbus_address = cmd_list[2]

                                    if '.' in modbus_address:
                                        _address = modbus_address.split('.')
                                    else:
                                        _address = (modbus_address, -1)
                                    rr = modbus_client.read_holding_registers(int(_address[0]), 1)
                                    # rr = modbus_client.read_input_registers(int(_address[0]), 1)
                                    time.sleep(1)

                                    retry = 0
                                    while retry < 3 and isinstance(rr, ModbusIOException):
                                        retry += 1
                                        logger.info("Retry: %d", retry)
                                        rr = modbus_client.read_input_registers(int(_address[0]), 1)
                                        time.sleep(1)

                                    logger.info(rr)
                                    logger.info(type(rr))

                                    if isinstance(rr, ModbusIOException) or isinstance(rr, ExceptionResponse):
                                        cmd_list.append("failed")
                                    else:
                                        if int(_address[1]) >= 0:
                                            cmd_list.append(str(get_bit(int(rr.registers[0]), int(_address[1]))))
                                        else:
                                            cmd_list.append(str(rr.registers[0]))
                                        cmd_list.append("success")
                                    s.send(':'.join(cmd_list).encode())
                                    logger.info("SENT: %s", ':'.join(cmd_list).encode())
                                if cmd_list[1] == 'set':
                                    modbus_address = cmd_list[2]
                                    if int(modbus_address) == 0:  # set max speed of the inverter
                                        set_config_max_speed(cmd_list[3])
                                    else:
                                        rr = modbus_client.write_register(int(modbus_address), int(cmd_list[3]))
                                        # modbus_client.write_registers(int(modbus_address), int(cmd_list[3]))
                                        time.sleep(1)

                                        logger.info(rr)
                                        logger.info(type(rr))

                                        retry = 0
                                        while retry < 3 and isinstance(rr, ModbusIOException):
                                            retry += 1
                                            logger.info("Retry: %d", retry)
                                            rr = modbus_client.write_register(int(modbus_address), int(cmd_list[3]))
                                            time.sleep(1)

                                        cmd_list.append('success')
                                    s.send(':'.join(cmd_list).encode())
                                if cmd_list[1] == 'keepalive' and cmd_list[2] == 'req':
                                    keepalive += 1

                                    modbus_client.write_registers(57, keepalive)
                                    time.sleep(1)

                                    cmd_list[2] = 'rsp'
                                    s.send(':'.join(cmd_list).encode())
                                if cmd_list[1] == 'set_config':
                                    s.send(':'.join(cmd_list).encode())
                        except Exception as e:
                            logger.error(e)
                            tcp_poller.unregister(s)
                            s.close()


def data_hub():
    client = gen_modbus_client()
    if not client:
        logger.error("Can't connect to device")
        return None
    # client.connect()
    data_map_path = os.path.join(os.path.dirname(__file__), "data_map2.json")
    with open(data_map_path, "r") as f:
        data_map = json.loads(f.read())

    while True:
        get_all_data(client, data_map)
        time.sleep(10)

# def post_data():

def get_all_data(client, data_map):
    for k, v in data_map.items():
        try:
            if "." not in k:
                rr = client.read_holding_registers(int(k), 1, unit=0x06)
                if isinstance(rr, ModbusIOException):
                    logger.error(rr)
                else:
                    logger.info("%s: %d%s", v.get('define'), rr.registers[0], v.get('unit'))
            else:
                address = k.split('.')
                rr = client.read_holding_registers(int(address[0]), 1, unit=0x06)
                if isinstance(rr, ModbusIOException):
                    logger.error(rr)
                else:
                    logger.info("%s: %d", v.get('define'), get_bit(int(rr.registers[0]), int(address[1])))
        except (ConnectionException,) as e:
            logger.error(e.string)


if __name__ == '__main__':
    gevent.joinall([
        gevent.spawn(cmd_server),
        gevent.spawn(data_hub)
    ])


