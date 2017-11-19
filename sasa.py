import re
import math
import struct


def swap32(i):
    return struct.unpack("<I", struct.pack(">I", i))[0]


def md5_encode(message):
    s = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
         4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

    k = [int(abs(math.sin(i + 1)) * 2**32) & 0xFFFFFFFF for i in range(64)]

    aa, bb, cc, dd = int('0x67452301', 16), int(
        '0xefcdab89', 16), int('0x98badcfe', 16), int('0x10325476', 16)
    a, b, c, d = aa, bb, cc, dd

    binmessage = ''.join('{0:08b}'.format(ord(x), 'b') for x in message)

    # appending 1 for padded zeros
    paddedmessage = binmessage + '1'

    # padding with zeros
    if (len(paddedmessage) + 64) % 512 == 0:
        pad = 0
    else:
        pad = 512 - (len(paddedmessage) + 64) % 512
    paddedmessage = paddedmessage + '0' * pad
    paddedmessage += "{0:064b}".format(len(binmessage))

    # Breaking into chunks of 32 bits
    brokenmessage = re.findall(
        '................................', paddedmessage)
    for i in range(0, len(brokenmessage)):
        brokenmessage[i] = swap32(int(brokenmessage[i], 2))
        brokenmessage[i] = "0x{:08x}".format(brokenmessage[i])

    temp = brokenmessage[14]
    brokenmessage[14], brokenmessage[15] = brokenmessage[15], temp
    brokenmessage[14] = swap32(int(brokenmessage[14], 16))
    brokenmessage[14] = "0x{:08x}".format(brokenmessage[14])

    print()
    print("Message blocks:", brokenmessage)
    print()

    for i in range(64):
        if 0 <= i <= 15:
            F = b & c | ((~b) & d)
            G = i
        elif 16 <= i <= 31:
            F = d & b | ((~d) & c)
            G = (5 * i + 1) % 16
        elif 32 <= i <= 47:
            F = b ^ c ^ d
            G = (3 * i + 5) % 16
        elif 48 <= i <= 63:
            F = c ^ (b | (~d))
            G = (7 * i) % 16
        #F = '0x{0:08x}'.format(F)
        #print("before add   ", F)
        F = (F + a + k[i] + int(brokenmessage[G], 16))
        a = d
        d = c
        c = b
        #print("aftere add   ", F)
        F = F & 0xFFFFFFFF
        intermediate = list("{0:032b}".format(F))
        intermediate = intermediate[s[i]::] + intermediate[:s[i]:]
        intermediate = ''.join(intermediate)
        F = int(intermediate, 2) & 0xFFFFFFFF
        #print("after rotate   ", F)
        b = (b + F) & 0xFFFFFFFF
        print("Iteration:", i, " A:", a, " B:", b, " C:", c, " D:", d)

    ans = [((aa + a) & 0xFFFFFFFF), ((bb + b) & 0xFFFFFFFF),
           ((cc + c) & 0xFFFFFFFF), ((dd + d) & 0xFFFFFFFF)]
    # extra added
    for i in range(0, 4):
        ans[i] = ans[i] << (32 * i)

    cipher = '{:032X}'.format(int.from_bytes(
        sum(ans).to_bytes(16, byteorder='little'), byteorder='big'))
    print()
    return cipher


if __name__ == '__main__':
    message = input("Enter plaintext: ")
    print("Md5 hashed cipher:  ", md5_encode(message))
