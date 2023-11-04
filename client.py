import threading
from socket import *
import json
import os
from os.path import join, getsize
import hashlib
import argparse
from threading import Thread
import struct
import time
import logging
from logging.handlers import TimedRotatingFileHandler
import base64
import uuid
import math
import shutil

# Const Value
OP_SAVE, OP_DELETE, OP_GET, OP_UPLOAD, OP_DOWNLOAD, OP_BYE, OP_LOGIN, OP_ERROR = 'SAVE', 'DELETE', 'GET', 'UPLOAD', 'DOWNLOAD', 'BYE', 'LOGIN', "ERROR"
TYPE_FILE, TYPE_DATA, TYPE_AUTH, DIR_EARTH = 'FILE', 'DATA', 'AUTH', 'EARTH'
FIELD_OPERATION, FIELD_DIRECTION, FIELD_TYPE, FIELD_USERNAME, FIELD_PASSWORD, FIELD_TOKEN = 'operation', 'direction', 'type', 'username', 'password', 'token'
FIELD_KEY, FIELD_SIZE, FIELD_TOTAL_BLOCK, FIELD_MD5, FIELD_BLOCK_SIZE = 'key', 'size', 'total_block', 'md5', 'block_size'
FIELD_STATUS, FIELD_STATUS_MSG, FIELD_BLOCK_INDEX = 'status', 'status_msg', 'block_index'
DIR_REQUEST, DIR_RESPONSE = 'REQUEST', 'RESPONSE'

ip, port, id = '', 1379, ''

#下面四个函数都是老师在server.py中提供的，可以直接拿来用
def _argparse():
    parse = argparse.ArgumentParser()
    parse.add_argument("--ip", default='', action='store', required=False, dest="ip",
                       help="The IP address bind to the server. Default bind to localhost.")
    parse.add_argument("--port", default='1379', action='store', required=False, dest="port",
                       help="The port that server listen on. Default is 1379.")
    parse.add_argument("--id", default='', action='store', required=False, dest="id",
                       help="Your id")
    # parse.add_argument("--f", default='', action='store', required=False, dest="file",
    #                    help="File path. Default is empty(No file will be upload)")
    # parse.add_argument("--thread", default='8', action='store', required=False, dest="total_thread",
    #                    help="The total number of thread. Default is 8")
    return parse.parse_args()

def make_packet(json_data, bin_data=None):
    """
    Make a packet following the STEP protocol.
    Any information or data for TCP transmission has to use this function to get the packet.
    :param json_data:
    :param bin_data:
    :return:
        The complete binary packet
    """
    j = json.dumps(dict(json_data), ensure_ascii=False)
    j_len = len(j)
    if bin_data is None:
        return struct.pack('!II', j_len, 0) + j.encode()
    else:
        return struct.pack('!II', j_len, len(bin_data)) + j.encode() + bin_data
def get_tcp_packet(conn):
    """
    Receive a complete TCP "packet" from a TCP stream and get the json data and binary data.
    :param conn: the TCP connection
    :return:
        json_data
        bin_data
    """
    bin_data = b''
    while len(bin_data) < 8:
        data_rec = conn.recv(8)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    data = bin_data[:8]
    bin_data = bin_data[8:]
    j_len, b_len = struct.unpack('!II', data)
    while len(bin_data) < j_len:
        data_rec = conn.recv(j_len)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    j_bin = bin_data[:j_len]

    try:
        json_data = json.loads(j_bin.decode())
    except Exception as ex:
        return None, None

    bin_data = bin_data[j_len:]
    while len(bin_data) < b_len:
        data_rec = conn.recv(b_len)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    return json_data, bin_data
def get_time_based_filename(ext, prefix='', t=None):
    """
    Get a filename based on time
    :param ext: ext name of the filename
    :param prefix: prefix of the filename
    :param t: the specified time if necessary, the default is the current time. Unix timestamp
    :return:
    """
    ext = ext.replace('.', '')
    if t is None:
        t = time.time()
    if t > 4102464500:
        t = t / 1000
    return time.strftime(f"{prefix}%Y%m%d%H%M%S." + ext, time.localtime(t))


#login_packet里面会使用到的json_data
def login_json_data(json_data):
    """
    json_data format: [type:AUTH, operation:LOGIN, direction:Request,
                       username:user_name(CLIENT_ID), password:password
                       tips: password实际上就是md5(user_name)就是对user_name做一个哈希算法从而
                             得到一个独一无二的字符串序列用做你的password
    :param json_data: In STEP message
    :param bin_data: None for AUTH type message
    :return:json_data
    """
    global id
    user_name = id
    password = hashlib.md5(user_name.encode()).hexdigest()
    json_data[FIELD_TYPE] = TYPE_AUTH
    json_data[FIELD_OPERATION] = OP_LOGIN
    json_data[FIELD_DIRECTION] = DIR_REQUEST
    json_data[FIELD_USERNAME] = user_name
    json_data[FIELD_PASSWORD] = password
    return json_data


#请求服务器认证，如果登录成功，会得到一个token
#token也是一个md5算法的结果,用作后续验证 (?)
def get_authorization(client_socket):
    """
    make login packet -> receive json data from server -> judge if login successfully
    :param client_socket: A client socket will be created in main function
    :return:token || None
    """
    #make login packet
    json_data = {}
    json_data = login_json_data(json_data)
    packet = make_packet(json_data, None)
    client_socket.send(packet)

    #receive json data from server
    recv_json_data, recv_bin_data = get_tcp_packet(client_socket)

    # Judge if login successfully
    # 如果收到的json_data里没有FIELD_TOKEN，那么返回None
    if FIELD_TOKEN not in recv_json_data:
        return None

    # 如果收到的json_data里有FIELD_TOKEN但是与原先生成的不相符,那么也返回None
    user_str = f'{json_data[FIELD_USERNAME].replace(".", "_")}.' \
               f'{get_time_based_filename("login")}'
    md5_auth_str = hashlib.md5(f'{user_str}kjh20)*(1'.encode()).hexdigest()
    if base64.b64encode(f'{user_str}.{md5_auth_str}'.encode()).decode() != recv_json_data[FIELD_TOKEN]:
        print('Token is wrong !')
        return None

    #否则接收并打印，返回token
    token = recv_json_data[FIELD_TOKEN]
    print(f'Token : {token}')
    return token


def main():
    #分析输入参数
    global ip, port, id
    parser = _argparse()
    server_ip = parser.ip
    server_port = int(parser.port)
    client_id = parser.id

    #建立TCP连接
    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect((server_ip, server_port))

    #获取验证
    token = get_authorization(client_socket)
    if token == None:
        return


if __name__ == '__main__':
    main()