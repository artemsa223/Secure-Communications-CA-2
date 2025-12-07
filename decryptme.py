import string
from base64 import b64encode, b64decode


# Read the intercepted ciphertext
try:
    with open('intercepted.txt', 'r') as f:
        ciphertext = f.read().strip()
    print(f"\n✓ Loaded ciphertext: {len(ciphertext)} characters\n")
except FileNotFoundError:
    print("\n✗ ERROR: intercepted.txt not found!")
    exit(1)

def reverse_step1(s):
    """
    Reverse step1: alphabet reversal substitution
    """
    if isinstance(s, bytes):
        s = s.decode('utf-8', errors='ignore')

    _step1_reverse = str.maketrans(
        "mlkjihgfedcbaMLKJIHGFEDCBAzyxwvutsrqponZYXWVUTSRQPON",
        "zyxwvutsrqponZYXWVUTSRQPONmlkjihgfedcbaMLKJIHGFEDCBA"
    )
    return s.translate(_step1_reverse)


def reverse_step2(s):
    """Reverse step2: base64 decoding"""
    try:
        if isinstance(s, str):
            s = s.encode('utf-8')
        result = b64decode(s)
        return result
    except Exception as e:
        print(f"  ERROR in base64 decode: {e}")
        return None


def reverse_step3(plaintext, shift=4):
    """Reverse step3: reverse Caesar cipher (shift backward by 4)"""
    if isinstance(plaintext, bytes):
        plaintext = plaintext.decode('utf-8', errors='ignore')

    loweralpha = string.ascii_lowercase
    # To reverse: shift backward
    shifted_string = loweralpha[-shift:] + loweralpha[:-shift]
    converted = str.maketrans(loweralpha, shifted_string)
    return plaintext.translate(converted)


print("✓ reverse_step1: Alphabet reversal")
print("✓ reverse_step2: Base64 decoding")
print("✓ reverse_step3: Caesar cipher reverse\n")

print("=" * 80)
print("DECRYPTION PROCESS")
print("=" * 80)

current_data = ciphertext
step_count = 0

while True:
    step_count += 1

    # Check if data starts with step indicator (1, 2, or 3)
    if not current_data or current_data[0] not in '123':
        print(f"\n✓ No more step indicators found!")
        print(f"✓ Decryption complete after {step_count - 1} steps")
        break

    if step_count > 100:  # Safety check
        print(f"\n⚠ WARNING: More than 100 steps detected, stopping for safety")
        break

    # Extract the step number
    step_num = int(current_data[0])
    step_data = current_data[1:]  # Data to decrypt

    print(f"\n[Step {step_count}] Found indicator: {step_num}")
    print(f"  Data length: {len(step_data)} characters")

    # Apply the reverse step
    try:
        if step_num == 1:
            print(f"  → Applying reverse_step1 (alphabet reversal)...", end=" ")
            current_data = reverse_step1(step_data)
            print(f"✓ ({len(current_data)} chars)")

        elif step_num == 2:
            print(f"  → Applying reverse_step2 (base64 decode)...", end=" ")
            current_data = reverse_step2(step_data)
            if current_data is None:
                print("ERROR!")
                break
            # After base64 decode, convert to string for next check
            if isinstance(current_data, bytes):
                current_data = current_data.decode('utf-8', errors='ignore')
            print(f"✓ ({len(current_data)} chars)")

        elif step_num == 3:
            print(f"  → Applying reverse_step3 (Caesar reverse)...", end=" ")
            current_data = reverse_step3(step_data)
            print(f"✓ ({len(current_data)} chars)")

    except Exception as e:
        print(f"ERROR: {e}")
        break

print("\n" + "=" * 80)
print("FINAL MESSAGE EXTRACTION")
print("=" * 80)

# Clean up the message
if isinstance(current_data, bytes):
    final_message = current_data.decode('utf-8', errors='ignore')
else:
    final_message = current_data

# Remove any leading/trailing whitespace
final_message = final_message.strip()

print(f"\nMessage length: {len(final_message)} characters")
print(f"Message type: {type(final_message)}")

print("\n" + "=" * 80)
print("DECRYPTED MESSAGE")
print("=" * 80)
print("\n" + final_message)
print("\n" + "=" * 80)

# Save to file
try:
    with open('decrypted_message.txt', 'w', encoding='utf-8') as f:
        f.write(final_message)
    print("\n✓ Message saved to: decrypted_message.txt")
except Exception as e:
    print(f"\n⚠ Could not save to file: {e}")

print("\n✓ Decryption complete!")
