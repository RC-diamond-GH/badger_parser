import base64
from Crypto.Cipher import ARC4

def decrypt_rc4(key, data):
    key = bytes.fromhex(key)
    data = base64.b64decode(data)
    cipher = ARC4.new(key)
    return cipher.decrypt(data)

key = '26 24 21 64 2C 71 2A 65'
data = open('./tmp.log', 'r').readline()
print(decrypt_rc4(key, data).decode('utf-8'))