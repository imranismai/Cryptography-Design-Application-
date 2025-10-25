import os
from typing import List

# --- HCSC Keystream Generator (Code from initial response must be included here) ---

def KSA_Modified(key: bytes) -> List[int]:
    """Key-Scheduling Algorithm (KSA) for SPA initialization."""
    S = list(range(256))
    j = 0
    key_len = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % key_len]) % 256
        S[i], S[j] = S[j], S[i]
    k_idx = sum(key) % 256
    S[S[k_idx]], S[k_idx] = S[k_idx], S[S[k_idx]]
    return S

def setup_lfsr_taps(S: List[int]) -> List[int]:
    """Dynamically sets up LFSR taps based on the initial SPA state."""
    taps = []
    taps.append((S[32] % 31) + 1)
    taps.append((S[64] % 31) + 1)
    taps.append((S[96] % 31) + 1)
    taps.append((S[128] % 31) + 1)
    taps = sorted(list(set(taps)), reverse=True)
    if not taps: return [32, 22, 2, 1]
    return taps

class HCSC_Keystream:
    """The Hybrid Chaos Stream Cipher (HCSC) Keystream Generator."""
    def __init__(self, key: bytes):
        if not 16 <= len(key) <= 32:
            raise ValueError("Key must be between 16 and 32 bytes.")
            
        self.S = KSA_Modified(key)
        self.taps = setup_lfsr_taps(self.S)
        
        lfsr_seed = int.from_bytes(key[:4], 'big')
        self.lfsr_state = lfsr_seed if lfsr_seed != 0 else 0xAAAAAAAA 
        
        self.i = 0
        self.j = 0

    def next_keystream_byte(self) -> int:
        """Generates the next 8-bit keystream value."""
        keystream_byte = 0
        for bit_pos in range(8):
            
            # 1. LFSR Step
            new_bit = 0
            for tap in self.taps:
                new_bit ^= ((self.lfsr_state >> (tap - 1)) & 1)
            self.lfsr_state = (self.lfsr_state >> 1) | (new_bit << 31)
            
            # 2. Chaotic S-Box Permutation
            self.i = (self.i + 1) % 256
            lfsr_influence = (self.lfsr_state & 0xFF)
            self.j = (self.j + self.S[self.i] + lfsr_influence) % 256
            self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]

            # 3. Output Generation
            t = (self.S[self.i] + self.S[self.j]) % 256
            keystream_bit = self.S[t] & 1 
            output_bit = new_bit ^ keystream_bit
            
            keystream_byte = (keystream_byte << 1) | output_bit

        return keystream_byte

# --- Core Cipher Functions ---

def hcsc_crypt(data: bytes, key: bytes, encrypt: bool) -> bytes:
    """Encrypts or decrypts data."""
    cipher = HCSC_Keystream(key)
    output = bytearray()
    for byte in data:
        keystream_byte = cipher.next_keystream_byte()
        encrypted_byte = byte ^ keystream_byte
        output.append(encrypted_byte)
    return bytes(output)

def hcsc_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Implements the encryption function."""
    return hcsc_crypt(plaintext, key, True)

def hcsc_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Implements the decryption function."""
    return hcsc_crypt(ciphertext, key, False)


# --- Demo with Your New Key and Plaintext ---

def demo_stream_cipher_final():
    """
    Demonstrates correct encryption and decryption with the custom key.
    """
    print("## HCSC Demo: Final Run with Custom Key 🔒")
    
    # 1. Setup
    # YOUR NEW CUSTOM KEY
    key_str = "UtPjanUary101997" 
    key = key_str.encode('utf-8')
    
    # YOUR PREVIOUSLY CHOSEN PLAINTEXT
    plaintext_str = "An interesting fact about Universiti Teknologi PETRONAS (UTP) is that in 2025, it achieved a ranking of 269 in the QS World University Rankings, making it a top private university in Malaysia and the ASEAN region."
    plaintext = plaintext_str.encode('utf-8')

    print(f"\n🔑 Key (ASCII): {key_str}")
    print(f"Key Length: {len(key)} bytes")
    print(f"📄 Plaintext Length: {len(plaintext)} bytes")
    
    # 2. Encryption
    print("\n--- Encryption Process ---")
    try:
        ciphertext = hcsc_encrypt(plaintext, key)
        print(f"✨ Ciphertext (Hex): {ciphertext.hex()}")
    except ValueError as e:
        print(f"Error during encryption: {e}")
        return

    # 3. Decryption
    print("\n--- Decryption Process ---")
    try:
        decrypted_bytes = hcsc_decrypt(ciphertext, key)
        decrypted_text = decrypted_bytes.decode('utf-8')
        
        print(f"✅ Decrypted Text: {decrypted_text}")
        
        # 4. Verification
        if decrypted_text == plaintext_str:
            print("\nVerification: SUCCESS! Cipher correctly encrypted and decrypted the text.")
        else:
            print("\nVerification: FAILED! Decrypted text does not match the original plaintext.")
            
    except ValueError as e:
        print(f"Error during decryption: {e}")

if __name__ == '__main__':
    demo_stream_cipher_final()

