table=[0x20,0x77,0xDF,0x77,0x4C,0x72,0x2C,0x43,0x3D,0x52,0x86,0xD9,0x0C,0xBC,0x1E,0x9B,0x88,0x72,0xE9,0x45,0xA1,0x1D,0x6D,0x3B,0xB2,0xD2,0xD9,0xAE,0xA4,0x15,0x2E,0x16,0x1B,0x73,0x94,0xEB,0x11,0x84,0x4C,0xCE]
for i in range(len(table)):
    table[i] ^= ord('A')
en_flag="@BdxRTbRBbjIVf`PEyqe^\^\|cc|JRubaGLytHeRI@jgNegHU[Myy]=="
tmp = []
dest = [0]*100
flag=""
for i in en_flag:
    tmp.append(ord(i)-61)
for i in range(len(tmp)//4):
    dest[i*3] = (tmp[i*4]<<2) | (tmp[i*4+1]>>4)
    dest[i*3 + 1] = ((tmp[i*4+1]&0b1111)<<4) | (tmp[i*4+2]>>2)
    dest[i*3 + 2] = ((tmp[i*4+2]&0b11) << 6) | (tmp[i*4+3])
for i in range(40):
    flag+=chr((dest[i])^table[i])
print(flag)