import os

qword_AA7388 = {
    'rax':r'\x48\xB8',
    'rbx':r'\x48\xBB',
    'rcx':r'\x48\xB9',
    'rdx':r'\x48\xBA',
    'rsi':r'\x48\xBE',
    'rdi':r'\x48\xBF',
    'r8' :r'\x49\xB8',
    'r9' :r'\x49\xB9',
    'r10':r'\x49\xBA',
    'r11':r'\x49\xBB',
    'r12':r'\x49\xBC',
    'r13':r'\x49\xBD',
    'r14':r'\x49\xBE',
    'r15':r'\x49\xBF',
}
qword_AA7388_ = {
    'rax':[0x48, 0xB8],
    'rbx':[0x48, 0xBB],
    'rcx':[0x48, 0xB9],
    'rdx':[0x48, 0xBA],
    'rsi':[0x48, 0xBE],
    'rdi':[0x48, 0xBF],
    'r8' :[0x49, 0xB8],
    'r9' :[0x49, 0xB9],
    'r10':[0x49, 0xBA],
    'r11':[0x49, 0xBB],
    'r12':[0x49, 0xBC],
    'r13':[0x49, 0xBD],
    'r14':[0x49, 0xBE],
    'r15':[0x49, 0xBF]
}
qword_AA73A8 = {
    'rax':r'\x50',
    'rbx':r'\x53',
    'rcx':r'\x51',
    'rdx':r'\x52',
    'rsi':r'\x56',
    'rdi':r'\x57',
    'r8' :r'\x41\x50',
    'r9' :r'\x41\x51',
    'r10':r'\x41\x52',
    'r11':r'\x41\x53',
    'r12':r'\x41\x54',
    'r13':r'\x41\x55',
    'r14':r'\x41\x56',
    'r15':r'\x41\x57'
}
qword_AA73A8_ = {
    'rax':[0x50],
    'rbx':[0x53],
    'rcx':[0x51],
    'rdx':[0x52],
    'rsi':[0x56],
    'rdi':[0x57],
    'r8' :[0x41, 0x50],
    'r9' :[0x41, 0x51],
    'r10':[0x41, 0x52],
    'r11':[0x41, 0x53],
    'r12':[0x41, 0x54],
    'r13':[0x41, 0x55],
    'r14':[0x41, 0x56],
    'r15':[0x41, 0x57]
}

def ifStartWith(data, arr):
    if len(data) < len(arr):
        return False
    for i in range(len(arr)):
        if data[i] != arr[i]:
            return False
    return True

def main():
    tmpf = open('./tmp.log', 'r')
    s = tmpf.readline()
    tmpf.close()
    data = raw_string_to_bytes(s)
    bucket = []
    ori = len(data)
    while len(data) > 10:
        progress_bar(ori - len(data), ori)
        for x in qword_AA7388_.values():
            if ifStartWith(data, x):
                #print("A")
                bucket.append(data[len(x):len(x)+8])
                data = data[len(x)+8:]
                break
        for x in qword_AA73A8_.values():
            if ifStartWith(data, x):
                data = data[len(x):]
                break
    i = len(bucket)
    truedata = []
    while i > 0:
        i -= 1
        for x in bucket[i]:
            truedata.append(x)
    dump = open('./tmp', 'wb')
    for x in truedata:
        dump.write(bytes([x]))
    dump.close()

def raw_string_to_bytes(s):
    s = bytes(s, "utf-8").decode("unicode_escape")
    return [ord(c) for c in s]

def progress_bar(i, total):
    print('\r', '#'*int((i / total) * 100), ' '*int((total-i) / total * 100), '[{}/{}]'.format(i, total), end='')

if __name__ == '__main__':
    #main()
    for i in qword_AA7388_.values():
        print('({}, {}),'.format(hex(i[0]), hex(i[1])), end = '')
    print()
    for i in qword_AA73A8_.values():
        if len(i) == 1:
            print('({}), '.format(hex(i[0])), end = '')
        elif len(i) == 2:
            print('({}, {}), '.format(hex(i[0]), hex(i[1])), end = '')