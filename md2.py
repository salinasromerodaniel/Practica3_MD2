import struct
import fileinput
import math

import binascii

Sbox = [
    41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
    19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
 76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
 138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
 245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
 148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
 39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
 181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
 150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
 96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
 85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
 234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
 129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
 8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
 203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
 166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
 31, 26, 219, 153, 141, 51, 159, 17, 131, 20
]

block_size = 16  # 16 bytes or 128 bits

lines = []
for line in fileinput.input():
    lines.append(line)
message = lines[3].strip()
message_bytes = bytearray(message, 'utf-8')

padding = block_size - (len(message_bytes) % block_size)
message_bytes += bytearray(padding for _ in range(padding))

previous_checkbyte = 0  # Used as an Initialisation Vector (IV)
checksum = bytearray(0 for _ in range(block_size))

# Process each 16-word block (16 bytes per block)
for i in range(len(message_bytes) // block_size):
    # Calculate checksum of block using each byte of the block
    for j in range(block_size):
        byte = message_bytes[i * block_size + j]
        previous_checkbyte = checksum[j]  = Sbox[byte ^ previous_checkbyte] ^ checksum[j]

message_bytes += checksum

buffer_size = 48
digest = bytearray([0 for _ in range(buffer_size)])

n_rounds = 18

for i in range(len(message_bytes) // block_size):
    # Copy block i into the middle section of the array
    # The last section in the array is then filled with front section XOR middle section
    for j in range(block_size):
        digest[block_size + j] = message_bytes[i * block_size + j]
        digest[2 * block_size + j] = digest[block_size + j] ^ digest[j]

    # Rounds of encryption over the entire array. Current byte XOR'd with the previous (substituted) byte.
    previous_hashbyte = 0
    for j in range(n_rounds):
        for k in range(buffer_size):
            digest[k] = previous_hashbyte = digest[k] ^ Sbox[previous_hashbyte]

        previous_hashbyte = (previous_hashbyte + j) % len(Sbox)


print(binascii.hexlify(digest[:16]).decode('utf-8'))

