
import hashlib

# Target hash we need to find
target_hash = "c89aa2ffb9edcc6604005196b5f0e0e4"

# Starting point
current = ""
md5 = "ecsc"

print("=" * 70)
print("HASH CHAIN AUTHENTICATION CHALLENGE - SOLUTION")
print("=" * 70)
print(f"\nTarget: {target_hash}")
print(f"Starting: {md5}")
print("\nHashing chain backwards...\n")

# Keep hashing until we find the target
iteration = 0
while md5 != target_hash:
    current = md5
    md5 = hashlib.md5(md5.encode()).hexdigest()
    iteration += 1
    print(f"Iteration {iteration}: hash({current[:20]}...) = {md5[:20]}...")

print("\n" + "=" * 70)
print("SOLUTION FOUND!")
print("=" * 70)
print(f"\nX (predecessor hash): {current}")
print(f"Verification: hash({current})")
print(f"           = {md5}")
print(f"\nTarget hash:         {target_hash}")
print(f"Match: {md5 == target_hash} ✓")
print("\n" + "=" * 70)
