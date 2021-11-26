import math
import pandas as pd
import random
from Crypto.Random import get_random_bytes
from arc4 import arc4_ksa, arc4_prga, byte_xor

'''
The user can either make it a 64-bit WEP encryption (24-bit IV, 40-bit WEP key) or a 128-bit WEP encryption (24-bit IV, 104-bit WEP key).
'''

def get_plaintext(df):
    sentence_index = random.randint(0, len(df)-1)
    sentence = df.iat[sentence_index,0]
    return sentence

# Generate 24 bit (3 bytes) IVs of the format (A+3,255,X) => IVs in this format are targetted in the FMS attack
def generate_ivs(wep_key):
    list_of_ivs = []
    # Initialise list containing the individual 3 bytes of IV to be able to change value of each byte and joining them to form a complete 3 byte IV
    # The 2nd byte should always be 255 for FMS attack
    iv_bytes_list = [0,255,0]
    # A in the set [3,length of key (in bytes) + 3]
    for A in range(3, len(wep_key)+3):
        iv_bytes_list[0] = A
        # X is any value from the set [0,256)
        for X in range(256):
            iv_bytes_list[2] = X
            list_of_ivs.append(bytes(iv_bytes_list))
    return list_of_ivs

def wep_arc4(wep_key_bytes):
    # Save sentences into dataframe
    sentences_df = pd.read_fwf('sentences.txt', header=None, delimiter="\t")

    print()
    print("====================================================================")
    print("Generating suitable packets for Fluhrer, Mantin and Shamir attack...")
    print("====================================================================")
    print()

    # Generate 24 bit (3 bytes) IVs of the format (A+3,255,X)
    iv_list = generate_ivs(wep_key_bytes)
    iv_ciphertext_list = []
    
    for nonce in iv_list:
        # Concatenate the IV with the key to form a seed (64 bit, 8 bytes or 128 bit, 16 bytes) to use in ARC4
        seed = nonce + wep_key_bytes
        # Initialising S-box of ARC4 using seed
        s_box = arc4_ksa(seed)

        # Message you want to encrypt using WEP is converted to bytes and has SNAP header (0xAA) appended in front of message
        # Message is a random sentence from the list of sentences in 'sentences.txt'
        plaintext = bytes.fromhex('AA') + get_plaintext(sentences_df).encode('utf-8')
        # Get keystream and ciphertext generated from ARC4
        keystream, ciphertext = arc4_prga(plaintext,s_box)

        # 22 bytes packet data (IV || ciphertext) returned in hexadecimal
        iv_ciphertext = nonce + ciphertext
        iv_ciphertext_hex = iv_ciphertext.hex()
        iv_ciphertext_list.append(iv_ciphertext_hex)

    return iv_ciphertext_list