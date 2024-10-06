# 1. Constants (Tables for DES Permutation)
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

# Tables for key schedule and Feistel function
PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27, 19,
       11, 3, 60, 52, 44, 36, 63, 55,
       47, 39, 31, 23, 15, 7, 62, 54,
       46, 38, 30, 22, 14, 6, 61, 53,
       45, 37, 29, 21, 13, 5, 28, 20,
       12, 4]

PC2 = [14, 17, 11, 24, 1, 5, 3, 28,
       15, 6, 21, 10, 23, 19, 12, 4,
       26, 8, 16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55, 30, 40,
       51, 45, 33, 48, 44, 49, 39, 56,
       34, 53, 46, 42, 50, 36, 29, 32]

E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

SBOXES = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    # S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    # S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    # S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    # S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    # S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    # S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

# 2. Utility Functions
def string_to_bits(s):
    return [int(bit) for char in s for bit in bin(ord(char))[2:].zfill(8)]

def bits_to_string(bits):
    chars = []
    for b in range(0, len(bits), 8):
        byte = bits[b:b+8]
        chars.append(chr(int(''.join(str(bit) for bit in byte), 2)))
    return ''.join(chars)

def permutate(block, table):
    return [block[i - 1] for i in table]

def shift_left(bits, n):
    return bits[n:] + bits[:n]

def xor(bits1, bits2):
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

# 3. Key Generation
def generate_subkeys(key):
    key = permutate(key, PC1)
    left, right = key[:28], key[28:]
    subkeys = []
    
    for shift in SHIFTS:
        left = shift_left(left, shift)
        right = shift_left(right, shift)
        combined_key = left + right
        subkeys.append(permutate(combined_key, PC2))
    
    return subkeys

# 4. Feistel Round
def feistel(right, subkey):
    expanded_right = permutate(right, E)
    xored = xor(expanded_right, subkey)
    substituted = substitute(xored)
    return permutate(substituted, P)

def substitute(expanded_right):
    blocks = [expanded_right[i:i+6] for i in range(0, len(expanded_right), 6)]
    result = []
    for i, block in enumerate(blocks):
        row = int(f"{block[0]}{block[5]}", 2)
        col = int(''.join([str(x) for x in block[1:5]]), 2)
        val = SBOXES[i][row][col]
        result.extend([int(x) for x in bin(val)[2:].zfill(4)])
    return result

# 5. DES Encrypt and Decrypt
def des_encrypt(block, subkeys):
    block = permutate(block, IP)
    left, right = block[:32], block[32:]

    for i in range(16):
        left, right = right, xor(left, feistel(right, subkeys[i]))
    
    combined = right + left
    return permutate(combined, FP)

def des_decrypt(block, subkeys):
    block = permutate(block, IP)
    left, right = block[:32], block[32:]

    for i in range(16):
        left, right = right, xor(left, feistel(right, subkeys[15 - i]))
    
    combined = right + left
    return permutate(combined, FP)

# 6. Padding and Unpadding
def pad_message(message):
    padding_len = 8 - (len(message) % 8)
    return message + chr(padding_len) * padding_len

def unpad_message(message):
    padding_len = ord(message[-1])
    return message[:-padding_len]

# 7. Main DES Algorithm
def des(message, key, mode='encrypt'):
    if len(key) != 8:
        raise ValueError("Kunci harus 8 karakter.")

    # Convert message and key to bit arrays
    message = string_to_bits(message)
    key = string_to_bits(key)

    # Pad message if needed
    if mode == 'encrypt':
        message = string_to_bits(pad_message(bits_to_string(message)))

    # Generate subkeys
    subkeys = generate_subkeys(key)

    # Process each block of 64 bits
    result = []
    for i in range(0, len(message), 64):
        block = message[i:i+64]
        if mode == 'encrypt':
            result.extend(des_encrypt(block, subkeys))
        else:
            result.extend(des_decrypt(block, subkeys))

    # Convert result to string
    if mode == 'decrypt':
        return unpad_message(bits_to_string(result))
    
    return bits_to_string(result)

# Example usage:
key = "mysecret"
plaintext = "HelloWorld1234"

# Encrypt
ciphertext = des(plaintext, key, mode='encrypt')
print("Ciphertext:", ciphertext)

# Decrypt
decrypted = des(ciphertext, key, mode='decrypt')
print("Decrypted:", decrypted)
