import os
from typing import List

# --- Constants ---
# Your fixed, secret key (16 bytes long)
KEY_STRING = "UtPjanUary101997"
KEY = KEY_STRING.encode('utf-8')


# --- Helper Functions for SPA and LFSR (The Core Cipher Base) ---

def KSA_Modified(key: bytes) -> List[int]:
    """
    Key-Scheduling Algorithm (KSA) for initializing the State Permutation Array (SPA).
    Uses a standard RC4-like initialization with an additional key-dependent swap for uniqueness.
    """
    S = list(range(256))
    j = 0
    key_len = len(key)

    for i in range(256):
        # RC4-like standard swap
        j = (j + S[i] + key[i % key_len]) % 256
        S[i], S[j] = S[j], S[i]
    
    # Unique modification: Additional key-dependent swap based on the key length
    k_idx = sum(key) % 256
    S[S[k_idx]], S[k_idx] = S[k_idx], S[S[k_idx]]

    return S

def setup_lfsr_taps(S: List[int]) -> List[int]:
    """
    Dynamically sets up LFSR taps based on the initial SPA state.
    This links the keystream generation to the key-dependent S-box.
    """
    taps = []
    # Use four distinct locations in the S-box to determine the four tap positions
    taps.append((S[32] % 31) + 1)
    taps.append((S[64] % 31) + 1)
    taps.append((S[96] % 31) + 1)
    taps.append((S[128] % 31) + 1)
    
    # Ensure taps are unique and sorted
    taps = sorted(list(set(taps)), reverse=True)
    if not taps: 
         # Fallback for extreme edge case (shouldn't happen)
         return [32, 22, 2, 1] 
         
    return taps

class HCSC_Keystream:
    """
    The Hybrid Chaos Stream Cipher (HCSC) Keystream Generator.
    Combines an LFSR with a chaotic S-box permutation.
    """
    def __init__(self, key: bytes):
        if not 16 <= len(key) <= 32:
            raise ValueError("Key must be between 16 and 32 bytes.")
            
        self.S = KSA_Modified(key)
        self.taps = setup_lfsr_taps(self.S)
        
        # Initialize LFSR state (32-bit register)
        lfsr_seed = int.from_bytes(key[:4], 'big')
        self.lfsr_state = lfsr_seed if lfsr_seed != 0 else 0xAAAAAAAA 
        
        self.i = 0 
        self.j = 0 

    def next_keystream_byte(self) -> int:
        """
        Generates the next 8-bit keystream value.
        """
        keystream_byte = 0
        for bit_pos in range(8):
            
            # 1. LFSR Step: Generate a candidate bit and update state
            new_bit = 0
            for tap in self.taps:
                new_bit ^= ((self.lfsr_state >> (tap - 1)) & 1)
            
            # Shift the new bit into the LSB
            self.lfsr_state = (self.lfsr_state >> 1) | (new_bit << 31)
            
            # 2. Chaotic S-Box Permutation (PRGA-like)
            self.i = (self.i + 1) % 256
            
            # Hybrid coupling: LFSR state influences S-box swap index
            lfsr_influence = (self.lfsr_state & 0xFF)
            self.j = (self.j + self.S[self.i] + lfsr_influence) % 256
            
            # Swap S[i] and S[j]
            self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]

            # 3. Output Generation: The keystream bit is a combination
            t = (self.S[self.i] + self.S[self.j]) % 256
            keystream_bit = self.S[t] & 1 
            
            # Final output is the LFSR bit XORed with the S-box bit
            output_bit = new_bit ^ keystream_bit
            
            # Shift the bit into the resulting byte (MSB first)
            keystream_byte = (keystream_byte << 1) | output_bit

        return keystream_byte

# --- Core Cipher Functions ---

def hcsc_crypt(data: bytes, key: bytes) -> bytes:
    """Encrypts or decrypts data using the HCSC stream cipher."""
    cipher = HCSC_Keystream(key)
    output = bytearray()

    for byte in data:
        keystream_byte = cipher.next_keystream_byte()
        encrypted_byte = byte ^ keystream_byte
        output.append(encrypted_byte)
        
    return bytes(output)

def hcsc_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Implements the encryption function."""
    # Note: In a stream cipher, encrypt and decrypt are the same function (XOR)
    return hcsc_crypt(plaintext, key)

def hcsc_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Implements the decryption function."""
    return hcsc_crypt(ciphertext, key)


# --- Interactive Demo (New Implementation) ---

def interactive_demo():
    """
    Allows the user to input a plaintext message for encryption and decryption.
    """
    print("\n=======================================================")
    print("      VorTex Stream Demo")
    print("=======================================================")
    print(f"🔑 Using fixed key: '{KEY_STRING}' ({len(KEY)} bytes)")
    print("-------------------------------------------------------")
    
    while True:
        try:
            plaintext_str = input("\nEnter your plaintext message (or type 'exit' to quit):\n> ")
            
            if plaintext_str.lower() == 'exit':
                print("\nDemo exiting. Goodbye!")
                break
            
            if not plaintext_str:
                print("Please enter a non-empty message.")
                continue

            # Convert input string to bytes using UTF-8 encoding
            plaintext = plaintext_str.encode('utf-8')
            
            print(f"\n[INFO] Plaintext: '{plaintext_str}'")
            print(f"[INFO] Plaintext length: {len(plaintext)} bytes")
            
            # 1. Encryption
            print("\n--- Step 1: Encrypting ---")
            ciphertext = hcsc_encrypt(plaintext, KEY)
            print(f"✨ Ciphertext (Hex): {ciphertext.hex()}")
            
            # 2. Decryption
            print("\n--- Step 2: Decrypting ---")
            decrypted_bytes = hcsc_decrypt(ciphertext, KEY)
            decrypted_text = decrypted_bytes.decode('utf-8')
            
            print(f"✅ Decrypted Text: '{decrypted_text}'")
            
            # 3. Verification
            if decrypted_text == plaintext_str:
                print("\n[VERIFICATION] SUCCESS! Decrypted text matches original plaintext.")
            else:
                print("\n[VERIFICATION] FAILED! An error occurred during the process.")
                
            print("\n-------------------------------------------------------")
            
        except ValueError as e:
            print(f"\n[ERROR] Cipher Initialization Error: {e}")
        except Exception as e:
            print(f"\n[ERROR] An unexpected error occurred: {e}")

if __name__ == '__main__':
    interactive_demo()
