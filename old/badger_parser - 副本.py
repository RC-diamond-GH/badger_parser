from Crypto.Cipher import ARC4
import base64

opcode_begin = {
    0x48:[0xB8, 0xBB, 0xB9, 0xBA, 0xBE, 0xBF],
    0x49:[0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF]
}
opcode_end = (
    (0x50, 0x53, 0x51, 0x52, 0x56, 0x57), 
    # 0x41
    (0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57)
)


def raw_string_to_bytes(s):
    s = bytes(s, "utf-8").decode("unicode_escape")
    return [ord(c) for c in s]

def getTrueData(data):
    i = len(data)
    truedata = []
    while i > 0:
        i -= 1
        for x in data[i]:
            truedata.append(x)
    return truedata

def getOpcodeStartIdx(i, data):
    while i < len(data):
        if data[i] == 0x48:
            if data[i + 1] in opcode_begin[0x48]:
                break
            i += 1
        elif data[i] == 0x49:
            if data[i + 1] in opcode_begin[0x49]:
                break
            i += 1
        else:
            i += 1
    return i

def getOpcodeData(i, data):
    thedata = []
    while i < len(data):
        if (data[i] == 0x48 and data[i + 1] in opcode_begin[0x48]) or (data[i] == 0x49 and data[i + 1] in opcode_begin[0x49]):
            thedata.append(data[i + 2 : i + 10])
            if data[i + 10] == 0x41 and data[i + 11] in opcode_end[1]:
                i += 12
            elif data[i + 10] in opcode_end[0]:
                i += 11
            else:
                break
        else:
            break
    return thedata, i

def hex_dump(data):
    for i in range(0, len(data), 16):
        print(' '.join('{:02X}'.format(x) for x in data[i:i+32]))

def decrypt_rc4(key, data):
    cipher = ARC4.new(key)
    return cipher.decrypt(data)

def decrypt_base64_rc4(key, data):
    data = base64.b64decode(data)
    cipher = ARC4.new(key)
    return cipher.decrypt(data)

def find_head(data, head = [0xe8, 0x00, 0x00, 0x00]):
    for i in range(len(data)):
        if data[i] == head[0]:
            if data[i + 1] == head[1] and data[i + 2] == head[2] and data[i + 3] == head[3]:
                return i
    return -1


class BadgerConfig:
    def __init__(self, info):
        infos = info.split('|')
        self.sleep = infos[1]
        self.jitter = infos[2]
        self.ip = infos[11]
        self.port = infos[12]
        self.ua = infos[13]
        self.auth = infos[14]
        self.aes = infos[15]
        self.uri = infos[16]
        self.header = infos[17]
        self.unknown = infos[18]

def BadgerParser(badger):
    badger = badger[find_head(badger):]
    dll_data = []

    i = 0
    i = getOpcodeStartIdx(i, badger, 'start handle config data')
    print('config start at {}'.format(hex(i)))
    config_data, i = getOpcodeData(i, badger)
    print('config end at {}'.format(hex(i)))

    i = getOpcodeStartIdx(i, badger, 'start handle dll data')
    print('dll start at {}'.format(hex(i)))
    dll_data, i = getOpcodeData(i, badger)
    print('dll end at {}'.format(hex(i)))
    

    config_data = getTrueData(config_data)
    dll_data = bytes(getTrueData(dll_data))
    
    key1 = dll_data[len(dll_data) - 8:]
    dll_data = dll_data[:len(dll_data) - 8]
    hex_dump(key1)
    dll_data = decrypt_rc4(key1, dll_data)
    key2 = dll_data[len(dll_data) - 8:]
    hex_dump(key2)
    c = bytes(config_data)
    print(c)
    config = decrypt_base64_rc4(key2, c)
    print(config.decode('utf-8'))
    config = BadgerConfig(config.decode('utf-8'))

def main():
    f = open('./badger_x64.dll', 'rb')
    data = f.read()
    f.close()
    BadgerParser(data)

    
if __name__ == '__main__':
    main()