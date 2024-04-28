import pyshark
import struct
import socket
import json
from badger_parser import *

pcapng = 'badger.pcapng'
badger_file = 'badger_x64.dll'
c2_host = '192.168.106.136'
decode_host = '10.52.166.190'
decode_port = 9810
badgerConfig = None
conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn.connect((decode_host, decode_port))

def analyzePcapng():
    cap = pyshark.FileCapture(pcapng, display_filter = f'http && ip.addr == {c2_host}')
    http_data = []
    for packet in cap:
        if not 'HTTP' in packet:
            continue
        http_pkt = packet.http
        if hasattr(http_pkt, 'request_method') and http_pkt.request_method == 'POST' or hasattr(http_pkt, "response_code") and http_pkt.response_code == '200':
            if hasattr(http_pkt, 'file_data'):
                content = str(http_pkt.file_data)
                if content.startswith('->'):
                    http_data.append(content[2:-2])
                else:
                    http_data.append(content)
    return http_data

def initBadgerConfig():
    badger_data = open(badger_file, 'rb')
    global badgerConfig
    badgerConfig = BadgerParser(badger_data.read())
    badger_data.close()
    badgerConfig.printInfo()

def sendCMD(cmd, args):
    datad = bytes(args, encoding='utf-8')
    dataLen = len(datad)
    conn.send(struct.pack('<I', cmd))
    conn.send(struct.pack('<I', dataLen))
    conn.send(datad)

def sendAES():
    sendCMD(1, badgerConfig.aes)

def sendBase64(base64Str):
    sendCMD(2, base64Str)

def receivePacket():
    dataLen = struct.unpack('<I', conn.recv(4))[0]
    data = conn.recv(dataLen)
    return data

def main():
    print("==============================Badger Config=====================================")
    initBadgerConfig()
    print("================================================================================")
    httpDatas = analyzePcapng()
    sendAES()

    flows = []
    for x in httpDatas:
        sendBase64(x)
        data = receivePacket()
        flows.append(data.replace(b'\r', b'').replace(b'\n', b'').replace(b'\x00', b'').decode('utf-8'))
    
    for x in flows:
        if x.startswith('{'):
            j = json.loads(x)
            #print(j)
            if 'dt' in j:
                if 'chkin' in j['dt']:
                    j['dt']['chkin'] = base64.b64decode(j['dt']['chkin']).decode('utf-16')
            
            if 'mtdt' in j:
                if 'p_name' in j['mtdt']:
                    j['mtdt']['p_name'] = base64.b64decode(j['mtdt']['p_name']).decode('utf-16')

            print(j)

        elif x.startswith('b-0'):
            print(x)
        else:
            print(base64.b64decode(x).decode('utf-8'))
        print('--------------------------------------------------------------------------------')



if __name__ == '__main__':
    main()