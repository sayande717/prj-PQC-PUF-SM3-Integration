import os
import random
from cryptography.hazmat.primitives import hashes

CHALLENGE_LENGTH_BYTES = 32
SM3_DIGEST_LENGTH_BYTES = 32 
# Unique device fingerprint (Simulated)
SECRET_SEED = os.urandom(32) 
NOISE_RATE = 0.05 # = 5%
RESPONSE_BIT_LENGTH = SM3_DIGEST_LENGTH_BYTES * 8 

# Step 1: Ideal PUF
def generate_challenge(length: int = CHALLENGE_LENGTH_BYTES) -> bytes:
    """Generates a random challenge for the PUF."""
    return os.urandom(length)

def ideal_puf_function(challenge: bytes, secret_seed: bytes) -> bytes:
    """Produces the stable, deterministic 256-bit hash response."""
    hasher = hashes.Hash(hashes.SM3())
    hasher.update(secret_seed + challenge)
    return hasher.finalize()

# Step 2: Add Environmental Noise, at rate (NOISE_RATE * 100)%
# Noise is added by randomly flipping bits in the response
def apply_noise(ideal_response: bytes, noise_rate: float) -> bytes:
    noisy_response = bytearray(ideal_response)
    
    for i in range(RESPONSE_BIT_LENGTH):
        # Check if the current bit should be flipped based on the noise rate
        if random.random() < noise_rate:
            # Calculate byte index and bit position within the byte
            byte_index = i // 8
            bit_position = i % 8
            
            # Flip the specific bit using XOR
            noisy_response[byte_index] ^= (1 << bit_position)
            
    return bytes(noisy_response)

def simulated_puf_response(challenge: bytes, secret_seed: bytes) -> bytes:
    ideal_response = ideal_puf_function(challenge, secret_seed)
    noisy_response = apply_noise(ideal_response, NOISE_RATE)
    return noisy_response

# TEST CASE
# C_1 = generate_challenge()
# R_noisy_1 = simulated_puf_response(C_1, SECRET_SEED)
# R_noisy_2 = simulated_puf_response(C_1, SECRET_SEED)
# print(f"Response 1: {R_noisy_1.hex()}")
# print(f"Response 2: {R_noisy_2.hex()}")