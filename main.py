from helpers.puf_noise_1 import SECRET_SEED, generate_challenge, simulated_puf_response
from helpers.fuzzy_extract_2 import fe_generate, fe_reproduce
from helpers.sm3_protocol_3 import generate_nonce, generate_auth_tag, verify_auth_tag

print("STEP 1: Enrollment")

# 1. Generate challenge seed and get noisy PUF response
C_enroll = generate_challenge()
R_enroll_noisy = simulated_puf_response(C_enroll, SECRET_SEED)

# 2. Generate the Stable Key (K) and Helper Data (W)
K_stable, W = fe_generate(R_enroll_noisy)

# 3. Device Registration -> Verifier's Database
VERIFIER_DB = {
    "C_enroll": C_enroll,
    "W": W
}
print(f"> Stored Helper Data (W): {W.hex()}...")
print(f"> Stored Challenge (C): {C_enroll.hex()}...")

# Verifier stores W & C_enroll for future authentication

print("\nSTEP 2: Authentication")

C_auth = VERIFIER_DB["C_enroll"]
W_auth = VERIFIER_DB["W"]
Nonce = generate_nonce()

print("\nCase 2.1: Simulating Auth SUCCESS")

print(f"> Verifier sends Challenge C and Helper Data W, and Nonce: {Nonce.hex()}...")

# Device <- R_auth_noisy
R_auth_noisy = simulated_puf_response(C_auth, SECRET_SEED)

# Device -> K_reproduced
K_reproduced = fe_reproduce(R_auth_noisy, W_auth)

# Device -> Auth_Tag
Auth_Tag = generate_auth_tag(K_reproduced, C_auth, Nonce)
print(f"> Computed Tag: {Auth_Tag.hex()}...")

# CHECK
is_authenticated = verify_auth_tag(K_reproduced, C_auth, Nonce, Auth_Tag)
print("Result: ",end="")
print("Authentication successful." if is_authenticated else "Authentication failed.")

print("\n")

print("Case 2.2: Simulating Auth FAILURE")
Nonce = generate_nonce()
print(f"> Verifier sends Challenge C and Helper Data W, and Nonce: {Nonce.hex()}...")

# Flip some bits to add enough noise (just above correction threshold)
# Device <- R_auth_noisy
R_auth_noisy = bytes([b ^ 0xFF for b in simulated_puf_response(C_auth, SECRET_SEED)])

# Device -> K_reproduced
K_reproduced = fe_reproduce(R_auth_noisy, W_auth)

# Device -> Auth_Tag
Auth_Tag = generate_auth_tag(K_reproduced, C_auth, Nonce)
print(f"> Computed Tag: {Auth_Tag.hex()}...")

# CHECK
is_authenticated = verify_auth_tag(K_stable, C_auth, Nonce, Auth_Tag)
print("Result: ",end="")
print("Authentication successful." if is_authenticated else "Authentication failed.")


# Checking how the noisy response differs from the enrollment response
def noisy_difference(response_enroll, response_noisy):
    diff = bytes(a ^ b for a, b in zip(response_enroll, response_noisy))
    hamming_distance = sum(bin(x).count('1') for x in diff)
    return hamming_distance

# print(f'\nBit difference between Enrollment and Authentication responses: {noisy_difference(R_enroll_noisy, R_auth_noisy)} bits')