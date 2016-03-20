# -*- coding: utf-8 -*-
# https://developer.mozilla.org/ja/docs/WebSockets-840092-dup/Writing_WebSocket_servers
# https://gist.github.com/rich20bb/4190781

import sys
import socket
import hashlib
import base64
import select
import struct
#from logging import getLogger, StreamHandler, basicConfig, DEBUG
#from logging.handlers import TimedRotatingFileHandler

#LOG_FILENAME = 'socket_server.log'
#logger = getLogger(__name__)
#stream_handler = StreamHandler().setLevel(DEBUG)
#basic_config = basicConfig(filename=LOG_FILENAME,level=DEBUG)
#rotate_handler = TimedRotatingFileHandler(filename=LOG_FILENAME, when='D')

#logger.setLevel(DEBUG)
#logger.addHandler(stream_handler)
#logger.addHandler(basic_config)
#logger.addHandler(rotate_handler)

import logging
import logging.config
logging.config.fileConfig("log.conf")


HOST = "192.168.1.101"
HTTP_PORT = "8888"
WEBSOCKET_PORT = "9999"
WEBSOCKET_LISTENSIZE = 5
WEBSOCKET_BUFSIZE = 4096
WEBSOCKET_MAGIC_NUMBER = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def get_handshake_header(client_key):
    """
    """
    # Create sec-websocket-accept string
    keyword = client_key + WEBSOCKET_MAGIC_NUMBER 
    keyhash = hashlib.sha1(keyword).digest()
    accept_string = base64.b64encode(keyhash)
    
    # Create websocket handshake string
    handshake_header = (
        "HTTP/1.1 101 Web Socket Protocol Handshake\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "WebSocket-Origin: http://%(host)s:%(http_port)s\r\n"
        "WebSocket-Location: ws://%(host)s:%(websocket_port)s/\r\n"
        "Sec-WebSocket-Accept: %(accept_key)s\r\n"
        "\r\n" 
    ) % {
        'host': HOST,
        'http_port': HTTP_PORT,
        'websocket_port': WEBSOCKET_PORT,
        'accept_key': accept_string
    }
       
    return handshake_header


def decodeCharArray(stringStreamIn):
    """
    """
    # Turn string values into opererable numeric byte values
    byteArray = [ord(character) for character in stringStreamIn]
    datalength = byteArray[1] & 127
    indexFirstMask = 2

    if datalength == 126:
        indexFirstMask = 4
    elif datalength == 127:
        indexFirstMask = 10

    # Extract masks
    masks = [m for m in byteArray[indexFirstMask : indexFirstMask+4]]
    indexFirstDataByte = indexFirstMask + 4
    
    # List of decoded characters
    decodedChars = []
    i = indexFirstDataByte
    j = 0
    
    # Loop through each byte that was received
    while i < len(byteArray):
    
        # Unmask this byte and add to the decoded buffer
        decodedChars.append( chr(byteArray[i] ^ masks[j % 4]) )
        i += 1
        j += 1

    # Return the decoded string
    return decodedChars


def create_message(msg):
    """
    """  
    recvmsg = ""
    
    txt = 0x01
    b1 = 0x80
    b2 = 0
    
    b1 |= txt
    payload = msg.encode('utf-8')
    
    recvmsg += chr(b1)
    length = len(payload)
    
    if length < 126:
        b2 |= length
        recvmsg += chr(b2)
    
    elif length < (2 ** 16) -1:
        b2 |= 126
        recvmsg += chr(b2)
        recvmsg += struct.pack(">H", length)
        
    else:
        b2 |= 127
        message += chr(b2)
        recvmsg += struct.pack(">Q", length)
    
    recvmsg += payload
    return recvmsg
       

def send_message(client, message):
    """
    """
    recvmsg = create_message(message)
    logging.info(message)
    
    client.send(recvmsg)


def send_broadcast(socklist, selfsock, sock, message):
    """
    """
    recvmsg = create_message(message)
    logging.info(message)
    
    for rsock in socklist:
        if rsock != selfsock and rsock != sock:
            try:
                rsock.send(recvmsg)
                
            except Exception as e:
                print(e)
                rsock.close()
                socklist.remove(rsock)
    

def main():
    """
    """
    print("start websocket server")
    logging.info("start websocket server")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, int(WEBSOCKET_PORT)))
    sock.listen(WEBSOCKET_LISTENSIZE)
    
    print("listen port: " + WEBSOCKET_PORT)
    logging.info("listen port: " + WEBSOCKET_PORT)
    
    socklist = []
    socklist.append(sock)

    while True:
        read_sockets, write_sockets, error_sockets = select.select(socklist, [], [])
        for rsock in read_sockets:
            if rsock == sock:
                sockfd, addr = sock.accept()
                socklist.append(sockfd)

                msg = sockfd.recv(WEBSOCKET_BUFSIZE)

                [head, body] = msg.split("\r\n", 1)
                header = {}

                for line in body.splitlines():
                    if line == "":
                        break
                    else:
                        [key, value] = line.split(": ", 1)
                        header[key] = value.strip()
            
                client_key = header["Sec-WebSocket-Key"].rstrip()
                handshake_header = get_handshake_header(client_key)
                            
                sockfd.send(handshake_header)
            
            else:
                try:
                    data = decodeCharArray(rsock.recv(WEBSOCKET_BUFSIZE))
                    msg = ''.join(data).strip().decode('utf-8')                 

                    #send_message(rsock, msg)
                    send_broadcast(socklist, rsock, sock, msg)
                    
                except Exception as e:
                    print(e)
                    rsock.close()
                    socklist.remove(rsock)


if __name__ == '__main__':
    main()