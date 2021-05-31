#!/usr/bin/env python3
import sys
import base64


##########
# Name: tridium_niagara_legacy_decode.py
# Purpose: Tridium Niagara legacy passwords, extracted from 'config.bog' files, can
#          be decoded. This script takes a file of Base64 encoded passwords. It outputs
#          the decoded passwords. AES encrypted passwords will no decode properly. 
#          Legacy encoded passwords will decode to the plaintext password. Reversing
#          the password encoding was achieved by reviewing the applications's JAR files.
# Reference: Google's Buildings Hackable: https://blogs.blackberry.com/en/2013/05/Google-s-Buildings-Hackable
# Author: Don C. Weber (@cutaway) - Cutaway Security, LLC.
# 
# WARNING: Automated install of third-party software and tools we do not control.
# WARNING: No warranty or guarantee these tools are secure or do not contain malicious code.
# WARNING: Check all installed software on your own before use.
# WARNING: USE AT YOUR OWN RISK.
##########

SECRET = [
    144, 44, 183, 64, 188, 145, 38, 103, 129, 102, 78, 173, 228, 98, 183, 55, 106, 211, 76, 
    168, 211, 28, 155, 15, 99, 5, 53, 111, 201, 161, 183, 70, 145, 131, 232, 189, 255, 64, 
    222, 213, 168, 100, 37, 38, 242, 27, 243, 153, 182, 174, 159, 224, 120, 187, 166, 250, 
    138, 165, 147, 181, 77, 24, 99, 93, 43, 198, 35, 123, 235, 102, 53, 26, 68, 229, 227, 71, 
    245, 124, 101, 118, 113, 143, 36, 105, 122, 54, 160, 255, 197, 181, 140, 130, 216, 235, 
    203, 12, 15, 174, 170, 133, 7, 93, 163, 128, 161, 237, 27, 50, 153, 133, 173, 104, 165, 
    118, 176, 244, 178, 36, 199, 15, 71, 3, 164, 169, 184, 118, 215, 255, 64, 95, 12, 80, 159, 
    58, 141, 226, 121, 103, 199, 134, 240, 178, 214, 28, 238, 160, 33, 253, 252, 114, 64, 107, 
    248, 146, 250, 100, 224, 130, 87, 68, 149, 222, 251, 66, 73, 46, 22, 126, 187, 236, 78, 
    237, 199, 61, 250, 229, 235, 232, 186, 160, 193, 216, 240, 99, 146, 167, 102, 26, 163, 
    128, 58, 216, 204, 168, 66, 137, 106, 18, 211, 59, 76, 132, 232, 37, 22, 190, 31, 98, 98, 
    57, 80, 12, 183, 107, 2, 88, 106, 3, 232, 72, 104, 47, 182, 231, 101, 55, 70, 189, 243, 
    147, 94, 96, 106, 29, 181, 17, 131, 165, 126, 24, 254, 169, 79, 55, 103, 41, 232, 219, 
    56, 150, 39, 125, 3]

def decode(input_str):
    paramArrayOfByte = bytearray(base64.b64decode(input_str)[1:])
    i = len(SECRET)
    b1 = ((paramArrayOfByte[0] & 0xFF) << 24) + ((paramArrayOfByte[1] & 0xFF) << 16) + ((paramArrayOfByte[2] & 0xFF) << 8) + (paramArrayOfByte[3] & 0xFF)
    b2 = int((b1 ^ 0x7E9AB3E2) / 3) - 374573 >> 17
    b3 = 4
    while b3 < len(paramArrayOfByte):
        paramArrayOfByte[b3] = paramArrayOfByte[b3] ^ SECRET[b2 % i]
        b2 += 1
        b3 += 1
    b3 = 4
    while (b3 < len(paramArrayOfByte)):
        if ((paramArrayOfByte[b3] == 0) and (paramArrayOfByte[b3 + 1] == 0)):
            break
        b3 += 1
    b4 = (b3 - 4) >> 1;
    b5 = 0
    arrayOfChar = bytearray(b' ' * b4)
    while(b5 < b4):
        b = b5 * 2 + 4
        c = (((paramArrayOfByte[b] & 0xFF) << 8) + (paramArrayOfByte[b + 1] & 0xFF)) & 0xFF;
        arrayOfChar[b4 - b5 - 1] = c;
        b5 += 1
    return(arrayOfChar)

inf = sys.argv[1]
with open(inf, 'r') as fh:
    for line in fh:
        dl = decode(line.strip())
        print('##### Encoded: %s #####'%(line[:16]))
        print('Decoded: %s\n'%(dl))

