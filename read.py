import ida_bytes
import ida_segment

# 替换为您想要读取的内存段的实际起始和结束地址
start_address = 0x000000C000148000
end_address = start_address + 0xd3
# 获取内存段内容
segment_content = ida_bytes.get_bytes(start_address, end_address - start_address)

# 将内容以 hexdump 的形式写入 tmp.txt
with open('E:\\projects\\BRC4\\badger_parser\\tmp.txt', 'w') as f:
    hexdump = ' '.join(f'{b:02X}' for b in segment_content)
    f.write(hexdump)

# 将内容以 binary 的形式写入 tmp.bin
with open('E:\\projects\\BRC4\\badger_parser\\tmp.bin', 'wb') as f:
    f.write(segment_content)

# 将内容以 ASCII 字符串的形式写入 tmp.log
with open('E:\\projects\\BRC4\\badger_parser\\tmp.log', 'w') as f:
    ascii_string = ''.join(chr(b) if 32 <= b <= 127 else '.' for b in segment_content)
    f.write(ascii_string)

print("Memory segment content has been written to files.")
