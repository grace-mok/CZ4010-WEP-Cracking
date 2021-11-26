from packets import create_packets
from arc4 import byte_xor

def wep_cracking():
    # Genereate suitable packets for Fluhrer, Mantin and Shamir attack
    packets_df, actual_wep_key = create_packets()

    print()
    input("PRESS ENTER TO CONTINUE TO THE CRACKING OF THE WEP PASSWORD...")

    print()
    print("====================================================================")
    print("Cracking of WEP key in progress...")
    print("====================================================================")
    print()

    # The key length in bytes is the largest value of A+1 in IV (A+3,255,n)
    key_length = int(packets_df['iv'].iloc[len(packets_df)-1][:2],16) - 3 + 1
    seed_length = key_length + 3  # WEP key length in terms of bytes + iv length (3 bytes)
    seed_guess = [None,None,None] # Initialise an empty array of 3 elements for seed guess (to allow overwritting of iv bytes)

    # A is the index of the byte of the key we are guessing
    for A in range(3,key_length+3):
        next_byte_guess = {}
        # Iterate through each packet in dataframe
        for row_number in range(len(packets_df)):
            # Every packet has a different IV, so need re-extract IVs
            seed_first_3_bytes = bytes.fromhex(packets_df['iv'].iloc[row_number])
            seed_guess[0] = seed_first_3_bytes[0]
            seed_guess[1] = seed_first_3_bytes[1]
            seed_guess[2] = seed_first_3_bytes[2]
            
            # Decipher first byte of keystream by XORing with SNAP header (0xAA)
            ciphertext_first_byte = bytes.fromhex(packets_df['ciphertext'].iloc[row_number])
            keystream_first_byte = byte_xor(ciphertext_first_byte, b'\xAA')

            # Initialise S-box
            s_box = []
            for i in range(256):
                s_box.append(i)
            
            # Do the first (A+3)-1 iterations of KSA using IV bytes and known key bytes
            j = 0
            for i in range(len(seed_guess)):
                j = (j + s_box[i] + seed_guess[i % seed_length]) % 256
                s_box[i], s_box[j] = s_box[j], s_box[i]
                # Track the value of s_box[0] and s_box[1] after the second iteration
                if i == 1:
                    sbox_0, s_box1 = s_box[0], s_box[1]
            
            # Check that the scrambling in the PRGA is not done well
            # Do a mock PRGA for the current state of S-box
            i += 1
            x = s_box[1]
            if x + s_box[x] == A:
                # If values of s_box[0] and s_box[1] did not stay the same, their positions were swapped, so not weak IV, ignore
                if (sbox_0 != s_box[0] or s_box1 != s_box[1]):
                    continue
                
                # Else, the positions of 1st and 2nd byte in S-box did not swap at all, so take it as a weak IV
                derived_next_byte_value = (keystream_first_byte[0] - j - s_box[i]) % 256

                if derived_next_byte_value in next_byte_guess.keys():
                    next_byte_guess[derived_next_byte_value] += 1
                else:
                    next_byte_guess[derived_next_byte_value] = 1

        confirmed_next_byte = max(next_byte_guess, key=next_byte_guess.get)
        # Append the confirmed next byte to the seed_guess list
        seed_guess.append(confirmed_next_byte)
        
    print("Keystream (IV || WEP Key/Password) in Decimal equivalent of Bytes: ", seed_guess)
    print("** NOTE: Each list item represents a byte in the keystream.")
    print()

    # Convert the individual byte values (which are in decimal as of now) into hexadecimal values
    key_guess_hex_list = []
    for digit in seed_guess[3:]:
        hex_rep = hex(digit)[2:]
        # Check for number 0-9, and add extra '0' in front of the number
        if int(hex_rep, 16) < 10:
            hex_rep = "0" + hex_rep
        key_guess_hex_list.append(hex_rep)
    key_guess = ''.join(key_guess_hex_list)
    print("The password (in Hexadecimals) derived from the Fluhrer, Mantin and Shamir attack is: ", key_guess.upper())

    print()
    print("====================================================================")
    print("Comparing actual WEP key set and WEP key derived...")
    print("====================================================================")
    print()

    if actual_wep_key.upper() == key_guess.upper():
        print("The password derived from the Fluhrer, Mantin and Shamir attack is correct! WEP is cracked.")
    else:
        print("The password derived from the Fluhrer, Mantin and Shamir attack is incorrect! WEP is not cracked.")
        
wep_cracking()