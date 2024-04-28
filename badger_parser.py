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
    
    def printInfo(self):
        print('sleep: {}'.format(self.sleep))
        print('jitter: {}'.format(self.jitter))
        print('ip: {}'.format(self.ip))
        print('port: {}'.format(self.port))
        print('ua: {}'.format(self.ua))
        print('auth: {}'.format(self.auth))
        print('aes: {}'.format(self.aes))
        print('uri: {}'.format(self.uri))
        print('header: {}'.format(self.header))
        print('unknown: {}'.format(self.unknown))

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

def BadgerParser(badger):
    badger = badger[find_head(badger):]
    dll_data = []

    i = 0

    # start handle config data
    i = getOpcodeStartIdx(i, badger) # config data start here
    config_data, i = getOpcodeData(i, badger) # config data end here

    # start handle dll data
    i = getOpcodeStartIdx(i, badger) # dll data start here
    dll_data, i = getOpcodeData(i, badger) # dll data end here
    
    config_data = getTrueData(config_data)
    dll_data = bytes(getTrueData(dll_data))
    
    # Key1, RC4 key, to decrypt dll data
    key1 = dll_data[len(dll_data) - 8:]
    dll_data = dll_data[:len(dll_data) - 8]
    dll_data = decrypt_rc4(key1, dll_data)

    # Key2, RC4 key, to decrypt config data
    key2 = dll_data[len(dll_data) - 8:]
    c = bytes(config_data)
    config = decrypt_base64_rc4(key2, c)


    configObj = BadgerConfig(config.decode('utf-8'))
    return configObj

def main():
    f = open('./badger_x64.dll', 'rb')
    data = f.read()
    f.close()
    config = BadgerParser(data)
    config.printInfo()
    
if __name__ == '__main__':
    main()