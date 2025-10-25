# Block Cipher( NAMA : IronClaDBlockCipher)

import os
from typing import List, Tuple
import sys

# --- Constants ---
# Your fixed, secret key (16 bytes long)
KEY_STRING = "UtPjanUary101997"
KEY = KEY_STRING.encode('utf-8')

BLOCK_SIZE = 8       # 64 bits (8 bytes)
NUM_ROUNDS = 8       # Feistel rounds
PAD_BYTE = 0x80      # Start of PKCS#7-like padding
MASK_32 = 0xFFFFFFFF # 32-bit mask for 4-byte integers

# --- 1. Key Scheduling and Permutation Setup ---

def generate_subkeys(master_key: bytes) -> List[int]:
    """
    Generates 8 x 32-bit subkeys from the 16-byte (128-bit) master key.
    The key is simply split and recycled/mixed for the 8 rounds.
    """
    K = [int.from_bytes(master_key[i:i+4], 'big') for i in range(0, 16, 4)]
    # K = [K0, K1, K2, K3] (4 x 32-bit initial keys)
    
    subkeys = []
    # Generate 8 subkeys by cycling and mixing the initial 4 keys
    for r in range(NUM_ROUNDS):
        # Subkey = K[(r+1) % 4] rotated by r positions, XOR K[r % 4]
        key_part_1 = K[(r) % 4]
        key_part_2 = K[(r+1) % 4]
        
        # Simple ROR (Rotate Right)
        subkey = ((key_part_1 >> r) | (key_part_1 << (32 - r))) & MASK_32
        
        # XOR with another part of the key
        subkey = (subkey ^ key_part_2) & MASK_32
        
        subkeys.append(subkey)
        
    return subkeys

def create_s_box(key: bytes) -> List[int]:
    """
    Creates a simple 256-entry S-Box using a key-dependent KSA-like permutation.
    This ensures the S-box is unique for this key.
    """
    S = list(range(256))
    key_len = len(key)
    j = 0
    
    for i in range(256):
        j = (j + S[i] + key[i % key_len]) % 256
        S[i], S[j] = S[j], S[i]
        
    return S

# --- 2. Feistel F-Function (The Unique Round Function) ---

# Global S-Box and Subkeys are initialized later for efficiency
S_BOX = [] 
SUBKEYS = []

def F_function(R: int, subkey: int) -> int:
    """
    The unique F-function for the Sentinel Block Cipher (SBC).
    Input: 32-bit data (R), 32-bit subkey.
    Output: 32-bit mixed value.
    
    Logic: (Rotate + S-Box + Add Key)
    """
    # 1. Split R into 4 bytes
    b0 = (R >> 24) & 0xFF
    b1 = (R >> 16) & 0xFF
    b2 = (R >> 8) & 0xFF
    b3 = R & 0xFF
    
    # 2. S-Box Substitution (Non-Linearity)
    s0 = S_BOX[b0]
    s1 = S_BOX[b1]
    s2 = S_BOX[b2]
    s3 = S_BOX[b3]
    
    # 3. Diffusion (Mixing and Shifting)
    
    # Combined 32-bit value after S-Box
    S_mixed = (s0 << 24) | (s1 << 16) | (s2 << 8) | s3
    
    # Left Rotation (A key diffusion step)
    rotated = ((S_mixed << 5) | (S_mixed >> (32 - 5))) & MASK_32
    
    # 4. Key Addition (XOR the subkey)
    output = (rotated ^ subkey) & MASK_32
    
    return output

# --- 3. Padding and Block Handling ---

def pkcs7_pad(data: bytes) -> bytes:
    """Implements PKCS#7-like padding."""
    padding_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)

    # Reimplementing PKCS#7 correctly for robustness:
    if len(data) % BLOCK_SIZE == 0:
        # If block is full, add a full block of padding
        return data + bytes([BLOCK_SIZE] * BLOCK_SIZE)

    # Correctly implement PKCS#7 by appending the number of padding bytes
    return data + bytes([padding_len] * padding_len)


def pkcs7_unpad(data: bytes) -> bytes:
    """Removes PKCS#7-like padding."""
    if not data:
        return b''
    padding_len = data[-1]
    if padding_len > BLOCK_SIZE or padding_len == 0:
        # Check for invalid padding length (could indicate corruption)
        # We return the original data defensively if padding seems wrong
        return data 
    
    # Verify that all padding bytes match the length (standard PKCS#7 check)
    if all(byte == padding_len for byte in data[-padding_len:]):
        return data[:-padding_len]
    else:
        # Invalid padding structure, return unpadded data defensively
        return data

# --- 4. Core Cipher Operations ---

def encrypt_block(block: bytes, subkeys: List[int]) -> bytes:
    """Encrypts a single 64-bit block using 8-round Feistel network."""
    
    # Split the 64-bit block into two 32-bit halves (L0, R0)
    L = int.from_bytes(block[:4], 'big') & MASK_32
    R = int.from_bytes(block[4:], 'big') & MASK_32

    # Run 8 Feistel Rounds
    for r in range(NUM_ROUNDS):
        # Swap L and R, but use the old R as the new L
        L_next = R 
        
        # Calculate F-function: F = F(R_old, K_r)
        F_output = F_function(R, subkeys[r])
        
        # Calculate new R: R_next = L_old XOR F
        R_next = (L ^ F_output) & MASK_32
        
        # Update L and R
        L = L_next
        R = R_next
        
    # Final Swap (L8, R8) -> (R8, L8) is standard in Feistel
    ciphertext_block = R.to_bytes(4, 'big') + L.to_bytes(4, 'big')
    
    return ciphertext_block

def decrypt_block(block: bytes, subkeys: List[int]) -> bytes:
    """Decrypts a single 64-bit block using 8-round Feistel network 
    by running the rounds in reverse order with subkeys in reverse.
    """
    
    # L8 and R8 (which were R and L after the final swap in encryption)
    R = int.from_bytes(block[:4], 'big') & MASK_32
    L = int.from_bytes(block[4:], 'big') & MASK_32
    
    # Run 8 Feistel Rounds in Reverse
    for r in range(NUM_ROUNDS - 1, -1, -1):
        # Decryption: L_old = R_next XOR F(L_next, K_r)
        # L_old (R_next in encryption) is the R_current here
        # R_old (L_next in encryption) is the L_current here
        
        # Swap R and L, but use R as the new L (L_old)
        R_next = L
        
        # Calculate F-function: F = F(L_current, K_r)
        F_output = F_function(L, subkeys[r])
        
        # Calculate new R: L_old = R_current XOR F
        L_next = (R ^ F_output) & MASK_32
        
        # Update L and R
        L = L_next
        R = R_next
        
    # Final Swap: (R0, L0)
    plaintext_block = L.to_bytes(4, 'big') + R.to_bytes(4, 'big')
    
    return plaintext_block

def sbc_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypts a multi-block message."""
    global S_BOX, SUBKEYS
    S_BOX = create_s_box(key)
    SUBKEYS = generate_subkeys(key)
    
    padded_data = pkcs7_pad(plaintext)
    ciphertext = bytearray()
    
    for i in range(0, len(padded_data), BLOCK_SIZE):
        block = padded_data[i:i + BLOCK_SIZE]
        encrypted_block = encrypt_block(block, SUBKEYS)
        ciphertext.extend(encrypted_block)
        
    return bytes(ciphertext)

def sbc_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypts a multi-block message."""
    global S_BOX, SUBKEYS
    # Subkeys and S-Box must be initialized the same way as encryption
    S_BOX = create_s_box(key)
    SUBKEYS = generate_subkeys(key)
    
    decrypted_data = bytearray()
    
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        decrypted_block = decrypt_block(block, SUBKEYS)
        decrypted_data.extend(decrypted_block)
        
    return pkcs7_unpad(bytes(decrypted_data))

# --- 5. Interactive Demo ---

def interactive_demo_sbc():
    """
    Allows the user to input a plaintext message for encryption and decryption.
    """
    print("\n=======================================================")
    print("     Sentinel Block Cipher (SBC) Interactive Demo")
    print("=======================================================")
    print(f"🔑 Using fixed key: '{KEY_STRING}' ({len(KEY)} bytes)")
    print(f"Cipher Details: 64-bit Feistel Network, {NUM_ROUNDS} Rounds.")
    print("-------------------------------------------------------")
    
    while True:
        try:
            plaintext_str = input("\nEnter your plaintext message (or type 'exit' to quit):\n> ")
            
            if plaintext_str.lower() == 'exit':
                print("\nDemo exiting. Goodbye!")
                sys.exit(0) 
            
            if not plaintext_str:
                print("Please enter a non-empty message.")
                continue

            # Convert input string to bytes using UTF-8 encoding
            plaintext = plaintext_str.encode('utf-8')
            
            print(f"\n[INFO] Plaintext: '{plaintext_str}'")
            print(f"[INFO] Plaintext length: {len(plaintext)} bytes")
            
            # 1. Encryption
            print("\n--- Step 1: Encrypting Multi-Block Message ---")
            ciphertext = sbc_encrypt(plaintext, KEY)
            print(f"✨ Ciphertext (Hex): {ciphertext.hex()}")
            print(f"Blocks Encrypted: {len(ciphertext) // BLOCK_SIZE}")

            # 2. Decryption
            print("\n--- Step 2: Decrypting Multi-Block Message ---")
            decrypted_bytes = sbc_decrypt(ciphertext, KEY) 
            decrypted_text = decrypted_bytes.decode('utf-8')
            
            print(f"✅ Decrypted Text: '{decrypted_text}'")
            
            # 3. Verification
            if decrypted_text == plaintext_str:
                print("\n[VERIFICATION] SUCCESS! Decrypted text matches original plaintext.")
            else:
                print("\n[VERIFICATION] FAILED! An error occurred during the process.")
                
            print("\n-------------------------------------------------------")
            
        except Exception as e:
            print(f"\n[ERROR] An unexpected error occurred: {e}")

if __name__ == '__main__':
    interactive_demo_sbc()
