import base64
from Crypto.Cipher import ARC4

def decrypt_rc4(key, data):
    cipher = ARC4.new(key)
    return cipher.decrypt(data)

def main():
    f = open('./tmp.bin', 'rb')
    data = f.read()
    f.close()
    key = data[len(data) - 8:]
    data = data[0: len(data) - 8]
    print(decrypt_rc4(key, data).decode('utf-8'))

if __name__ == '__main__':
    main()