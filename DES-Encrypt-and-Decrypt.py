
# ---------------------------------------------------------------------------
# DES (Data Encryption Standard) – ECB mode implementation from scratch, no structured programming
# By Nambobi Mutwalibi, MSc, BSc
# This code implements the DES algorithm in Electronic Codebook (ECB) mode.
# It includes key scheduling, encryption, and decryption processes.ABC25156009EFABC
# The code is designed to be educational and illustrative of the DES algorithm's inner workings.
# ---------------------------------------------------------------------------
# --- Key and plaintext setup ---
plaintext = "mnambobi"                           # 8-character plaintext (64 bits)
key_hex    = "ABC25156009EFABC"                  # 16-hex-digit key (64 bits including parity)

# The and Plaintext 8 characters.and key must be exactly 16 hex characters (64 bits)
if len(plaintext) != 8:
    raise ValueError("Plaintext must be exactly 8 characters.")
if len(key_hex) != 16:
    raise ValueError("Your Key must be exactly 16 HEX characters.")

# Convert plaintext to a 64-bit binary string
plaintext_bits = ''.join(f"{ord(c):08b}" for c in plaintext)
# Convert hex key to 64-bit binary string
key_bits = f"{int(key_hex, 16):064b}"

# --- Key Schedule: generate 16 subkeys ---
# Permuted Choice 1 (PC-1): 64-bit key -> 56 bits
permutedChoice1 = [57,49,41,33,25,17,9,   1,58,50,42,34,26,18,
             10,2,59,51,43,35,27,  19,11,3,60,52,44,36,
             63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
             14,6,61,53,45,37,29, 21,13,5,28,20,12,4]
key56 = "".join(key_bits[i-1] for i in permutedChoice1)         # 56-bit key after dropping parity bits

# Split into two 28-bit halves
C = key56[:28]  # left half
D = key56[28:]  # right half

# Number of left shifts for each round (1 or 2)
shift_schedule = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# Permuted Choice 2 (PC-2): 56 -> 48 bits
permutedChoice2 = [14,17,11,24, 1, 5, 3,28, 15, 6,21,10,
             23,19,12, 4, 26, 8,16, 7, 27,20,13, 2,
             41,52,31,37, 47,55,30,40, 51,45,33,48,
             44,49,39,56, 34,53,46,42, 50,36,29,32]

round_keys_bin = []    # list to store 16 round keys in binary
round_keys_hex = []    # list to store 16 round keys in hex (for display)
for i in range(16):
    # Left circular shift the two halves
    shifts = shift_schedule[i]
    C = C[shifts:] + C[:shifts]
    D = D[shifts:] + D[:shifts]
    # Combine halves and apply PC-2 to get the 48-bit subkey
    combined_key = C + D
    subkey = "".join(combined_key[j-1] for j in permutedChoice2)
    round_keys_bin.append(subkey)
    round_keys_hex.append(f"{int(subkey, 2):012X}")   # store subkey in hex for display

# --- Encryption ---
# Initial Permutation on plaintext
initialPermutationTable = [58,50,42,34,26,18,10, 2, 60,52,44,36,28,20,12, 4,
            62,54,46,38,30,22,14, 6, 64,56,48,40,32,24,16, 8,
            57,49,41,33,25,17, 9, 1, 59,51,43,35,27,19,11, 3,
            61,53,45,37,29,21,13, 5, 63,55,47,39,31,23,15, 7]
ip_bits = "".join(plaintext_bits[i-1] for i in initialPermutationTable)
L = ip_bits[:32]   # Left half after IP
R = ip_bits[32:]   # Right half after IP
print("After initial permutation:", f"{int(ip_bits, 2):016X}")

# Define the E expansion table (32 -> 48 bits) for the Feistel function
expansion_table = [32, 1, 2, 3, 4, 5,  4, 5, 6, 7, 8, 9,
                    8, 9,10,11,12,13, 12,13,14,15,16,17,
                   16,17,18,19,20,21, 20,21,22,23,24,25,
                   24,25,26,27,28,29, 28,29,30,31,32, 1]

# S-box definitions (8 S-boxes, each a 4x16 table)
S_boxes = [
    [[14,4,13,1, 2,15,11,8, 3,10, 6,12, 5, 9, 0, 7],    # S1
     [ 0,15, 7,4,14, 2,13,1,10, 6,12,11, 9, 5, 3, 8],
     [ 4,1,14,8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0],
     [15,12, 8,2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13]],

    [[15,1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10],   # S2
     [ 3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5],
     [ 0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15],
     [13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9]],

    [[10,0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8],   # S3
     [13,7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1],
     [13,6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7],
     [ 1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12]],

    [[ 7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15],  # S4
     [13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9],
     [10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4],
     [ 3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14]],

    [[ 2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9],  # S5
     [14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6],
     [ 4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14],
     [11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3]],

    [[12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11],  # S6
     [10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8],
     [ 9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6],
     [ 4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13]],

    [[ 4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1],  # S7
     [13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6],
     [ 1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2],
     [ 6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12]],

    [[13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7],  # S8
     [ 1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2],
     [ 7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8],
     [ 2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11]]
]

# P-box permutation table (32-bit)
permutationTable = [16,7,20,21, 29,12,28,17, 1,15,23,26, 5,18,31,10,
               2,8,24,14, 32,27, 3, 9, 19,13,30, 6, 22,11, 4,25]

# 16 Feistel rounds
for i in range(16):
    # Expand R (32 -> 48 bits)
    R_expanded = "".join(R[j-1] for j in expansion_table)
    # XOR with round subkey (bitwise XOR on integers for clarity)
    xor_val   = int(R_expanded, 2) ^ int(round_keys_bin[i], 2)
    xor_bits  = f"{xor_val:048b}"
    # S-box substitution: 8 groups of 6 -> 8 groups of 4 bits
    sbox_output = ""
    for j in range(8):
        six_bits = xor_bits[j*6:(j+1)*6]
        row = int(six_bits[0] + six_bits[-1], 2)       # first and last bit form row (0-3)
        col = int(six_bits[1:5], 2)                    # middle 4 bits form col (0-15)
        sbox_val = S_boxes[j][row][col]
        sbox_output += f"{sbox_val:04b}"
    # Permutation P on the 32-bit S-box output
    f_output = "".join(sbox_output[k-1] for k in permutationTable)
    # Feistel swap: new L = old R, new R = old L XOR f_output
    new_L = R
    new_R = f"{int(L, 2) ^ int(f_output, 2):032b}"
    L, R = new_L, new_R
    print(f"Round {i+1:2d}: L={int(L,2):08X}, R={int(R,2):08X}, Subkey={round_keys_hex[i]}")

# After 16 rounds, combine R16 and L16 (note: R16 is current R, L16 is current L)
combined_block = R + L

# Final Permutation, inverse of initialPermutationTable
finalPermutationTable = [40,8,48,16, 56,24,64,32, 39,7,47,15, 55,23,63,31,
            38,6,46,14, 54,22,62,30, 37,5,45,13, 53,21,61,29,
            36,4,44,12, 52,20,60,28, 35,3,43,11, 51,19,59,27,
            34,2,42,10, 50,18,58,26, 33,1,41, 9, 49,17,57,25]
cipher_bits = "".join(combined_block[i-1] for i in finalPermutationTable)
cipher_hex  = f"{int(cipher_bits, 2):016X}"
print("Our Ciphertext (hex):", cipher_hex)

# --- Decryption ---
# Use ciphertext as input, perform initial permutation
initialPermutationCipher = "".join(cipher_bits[i-1] for i in initialPermutationTable)
L = initialPermutationCipher[:32]
R = initialPermutationCipher[32:]
print("Decrypt: after initial permutation:", f"{int(initialPermutationCipher, 2):016X}")

# Feistel rounds (using subkeys in reverse order)
for i in range(16):
    # Expand R (32 -> 48 bits)
    R_expanded = "".join(R[j-1] for j in expansion_table)
    # XOR with **reversed** round key
    xor_val  = int(R_expanded, 2) ^ int(round_keys_bin[15-i], 2)
    xor_bits = f"{xor_val:048b}"
    # S-box substitution (same as encryption steps)
    sbox_output = ""
    for j in range(8):
        six_bits = xor_bits[j*6:(j+1)*6]
        row = int(six_bits[0] + six_bits[-1], 2)
        col = int(six_bits[1:5], 2)
        sbox_val = S_boxes[j][row][col]
        sbox_output += f"{sbox_val:04b}"
    # P-box permutation
    f_output = "".join(sbox_output[k-1] for k in permutationTable)
    # Feistel swap (same as encryption step)
    new_L = R
    new_R = f"{int(L, 2) ^ int(f_output, 2):032b}"
    L, R = new_L, new_R
    print(f"Round {i+1:2d} (decryption): L={int(L,2):08X}, R={int(R,2):08X}, Subkey={round_keys_hex[15-i]}")

# Combine halves after 16 rounds and apply final permutation to get plaintext
combined_block_dec = R + L  # this is R16||L16 after decryption rounds
plain_bits = "".join(combined_block_dec[i-1] for i in finalPermutationTable)
recovered_hex  = f"{int(plain_bits, 2):016X}"
recovered_text = bytearray.fromhex(recovered_hex).decode('ascii', errors='ignore')
print("Decrypted plaintext (hex):", recovered_hex)
print("Decrypted plaintext (text):", recovered_text)
