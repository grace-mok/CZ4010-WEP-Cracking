# Function to XOR bytes bytewise
def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

# Key passed in as parameter should be in bytes
def arc4_ksa(key):
    # Initialise the S-box in ARC4
    s_box = []
    for i in range(256):
        s_box.append(i)
    
    j = 0
    for i in range(256):
        j = (j + s_box[i] + key[i % len(key)]) % 256
        s_box[i], s_box[j] = s_box[j], s_box[i]
    return s_box

def arc4_prga(plaintext, s_box):
    # Initialise list to append each byte of keystream into
    keystream = []
    j = 0
    # Generate a keystream from the key passed into ARC4 that is the same length as the plaintext
    for i in range(len(plaintext)):
        i = (i + 1) % 256
        j = (j + s_box[i]) % 256

        s_box[i], s_box[j] = s_box[j], s_box[i]
        keystream.append(s_box[(s_box[i] + s_box[j]) % 256])

    # Bytewise XOR keystream with plaintext to give ciphertext
    keystream_bytes = bytes(keystream)
    ciphertext = byte_xor(plaintext,keystream_bytes)
    return keystream_bytes, ciphertext