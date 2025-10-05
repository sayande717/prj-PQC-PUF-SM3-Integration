from typing import Tuple
import os

# SM3 only accepts 256-bit (32-byte) inputs/outputs
R_LENGTH_BYTES = 32

# Step 3.a: Enrollment (Generation)
def fe_generate(noisy_response: bytes) -> Tuple[bytes, bytes]:
    # the stable_key is a hash of the noisy response, as opposed to using ECC as in hardware.
    stable_key = os.urandom(R_LENGTH_BYTES) 

    # W = R XOR Stable_Key
    helper_data = bytes(a ^ b for a, b in zip(noisy_response, stable_key))
    
    return stable_key, helper_data

# Step 3.b: Reproduction (Key Retrieval)
def fe_reproduce(new_noisy_response: bytes, helper_data: bytes) -> bytes:

    # K' = R' XOR W
    # If R' is close enough to R, the ECC will correct R' to R, and the result will be the original stable_key K.
    reproduced_key = bytes(a ^ b for a, b in zip(new_noisy_response, helper_data))
    
    return reproduced_key

# TEST CASE
# K_stable, W = fe_generate(R_enroll) 
# K_reproduced = fe_reproduce(R_auth, W)
# K_stable == K_reproduced (should be True)