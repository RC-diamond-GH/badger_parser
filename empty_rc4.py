from Crypto.Cipher import ARC4

def decrypt_rc4(key, data):
    key = bytes.fromhex(key)
    cipher = ARC4.new(key)
    return cipher.decrypt(data)

def hex_dump(data):
    for i in range(0, len(data), 16):
        print(' '.join('{:02X}'.format(x) for x in data[i:i+32]))

key = '2a 20 23 69 73 6e 2f 71'
cipf = open('./tmp.bin', 'rb')
data = cipf.read()
cipf.close()
t = decrypt_rc4(key, data)
open('./tmp', 'wb').write(t)