import numpy as np
import hashlib
import hmac
import base64
import os

def pbkdf2_hmac_sha256(password, salt, iterations, dklen):
    try:
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen)
        return dk
    except Exception as e:
        print(f"Error in pbkdf2_hmac_sha256: {e}")
        raise

def derive_parameters(key1, key2):
    try:
        salt = hashlib.sha256(key1.encode('utf-8')).digest()
        dk = pbkdf2_hmac_sha256(key2, salt, 100000, 32)
        x0 = int.from_bytes(dk[:16], byteorder='big') / (1 << 128)
        mu = 1.5 + (int.from_bytes(dk[16:], byteorder='big') / (1 << 128)) * 0.5
        return x0, mu
    except Exception as e:
        print(f"Error in derive_parameters: {e}")
        raise

def tent_map(x, mu):
    try:
        if x < 0.5:
            return mu * x
        else:
            return mu * (1 - x)
    except Exception as e:
        print(f"Error in tent_map: {e}")
        raise

def logistic_map(x):
    try:
        r = 3.99
        return r * x * (1 - x)
    except Exception as e:
        print(f"Error in logistic_map: {e}")
        raise

def generate_chaotic_sequence(length, x0, mu):
    try:
        sequence = np.zeros(length)
        x = x0
        for i in range(length):
            x = logistic_map(tent_map(x, mu))
            sequence[i] = x
        return sequence
    except Exception as e:
        print(f"Error in generate_chaotic_sequence: {e}")
        raise

def key_influence(sequence, key1, key2):
    try:
        key1_bytes = np.frombuffer(key1.encode('utf-8'), dtype=np.uint8)
        key2_bytes = np.frombuffer(key2.encode('utf-8'), dtype=np.uint8)
        max_len = max(len(key1_bytes), len(key2_bytes))
        key1_bytes = np.tile(key1_bytes, max_len // len(key1_bytes) + 1)[:max_len]
        key2_bytes = np.tile(key2_bytes, max_len // len(key2_bytes) + 1)[:max_len]
        combined_key_bytes = (key1_bytes + key2_bytes) % 256
        key_sequence = np.repeat(combined_key_bytes, len(sequence) // len(combined_key_bytes) + 1)[:len(sequence)]
        return (sequence * 255 + key_sequence) % 256
    except Exception as e:
        print(f"Error in key_influence: {e}")
        raise

def encrypt_round(data, key1, key2):
    try:
        x0, mu = derive_parameters(key1, key2)
        data_bytes = np.frombuffer(data, dtype=np.uint8)
        iv = os.urandom(16)
        chaotic_sequence = generate_chaotic_sequence(len(data_bytes), x0, mu)
        influenced_sequence = key_influence(chaotic_sequence, key1, key2)
        ciphertext_bytes = np.bitwise_xor(data_bytes, influenced_sequence.astype(np.uint8))
        hmac_key = pbkdf2_hmac_sha256(key2, iv, 100000, 32)
        hmac_digest = hmac.new(hmac_key, iv + ciphertext_bytes.tobytes(), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(iv + ciphertext_bytes.tobytes() + hmac_digest).decode('utf-8')
    except Exception as e:
        print(f"Error in encrypt_round: {e}")
        raise

def encrypt(plaintext, key1, key2, rounds=2):
    try:
        ciphertext = plaintext.encode('utf-8')
        for _ in range(rounds):
            ciphertext = encrypt_round(ciphertext, key1, key2).encode('utf-8')
        return ciphertext.decode('utf-8')
    except Exception as e:
        print(f"Error in encrypt: {e}")
        raise

def decrypt_round(ciphertext, key1, key2):
    try:
        ciphertext_bytes = base64.urlsafe_b64decode(ciphertext)
        iv = ciphertext_bytes[:16]
        hmac_digest_received = ciphertext_bytes[-32:]
        encrypted_data = ciphertext_bytes[16:-32]
        hmac_key = pbkdf2_hmac_sha256(key2, iv, 100000, 32)
        hmac_digest_calculated = hmac.new(hmac_key, iv + encrypted_data, hashlib.sha256).digest()
        if not hmac.compare_digest(hmac_digest_received, hmac_digest_calculated):
            raise ValueError("HMAC verification failed, data may have been tampered with")
        x0, mu = derive_parameters(key1, key2)
        chaotic_sequence = generate_chaotic_sequence(len(encrypted_data), x0, mu)
        influenced_sequence = key_influence(chaotic_sequence, key1, key2)
        decrypted_data = np.bitwise_xor(np.frombuffer(encrypted_data, dtype=np.uint8), influenced_sequence.astype(np.uint8))
        return decrypted_data.tobytes()
    except Exception as e:
        print(f"Error in decrypt_round: {e}")
        raise

def decrypt(ciphertext, key1, key2, rounds=2):
    try:
        decrypted_text = ciphertext.encode('utf-8')
        for _ in range(rounds):
            decrypted_text = decrypt_round(decrypted_text.decode('utf-8'), key1, key2)
        return decrypted_text.decode('utf-8')
    except Exception as e:
        print(f"Error in decrypt: {e}")
        raise

def main():
    try:
        Aim = input("1 for encryption🔒, 2 for decryption🔑\nPlease enter: ")
        if Aim == "1":
            key1 = input("Enter key 1: ")
            key2 = input("Enter key 2: ")
            plaintext = input("Enter data to encrypt: ")
            rounds = int(input("Enter number of rounds: "))
            ciphertext = encrypt(plaintext, key1, key2, rounds)
            print("Ciphertext:\n", ciphertext)
        elif Aim == "2":
            key1 = input("Enter key 1: ")
            key2 = input("Enter key 2: ")
            ciphertext = input("Enter data to decrypt: ")
            rounds = int(input("Enter number of rounds: "))
            decrypted_text = decrypt(ciphertext, key1, key2, rounds)
            print("Plaintext:\n", decrypted_text)
        else:
            print("Invalid selection, please enter 1 or 2")
    except Exception as e:
        print(f"Error in main: {e}")

if __name__ == "__main__":
    main()