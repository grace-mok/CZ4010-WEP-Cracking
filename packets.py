import pandas as pd
import string
from wep import wep_arc4

def create_packets():
    packets = []
    iv = []
    ciphertext = []

    acceptable_input = False
    while not acceptable_input:
        # User sets 40 bit/5 bytes/10 Hexadecimal digits or 104 bit/13 bytes/26 hexadecimal digits password/key for WEP
        user_input = input("Please input 10 or 26 hexadecimal digits to set as WEP key: ")
        
        try:
            if (len(user_input) != 10 and len(user_input) != 26):
                print("Please input only 10 or 26 hexadecimal digits.")
                continue
            # Test that user input can be converted to hexadecimal successfully
            wep_key_hex = int(user_input, 16)
            wep_key_bytes = bytes.fromhex(user_input)
            acceptable_input = True
        except ValueError:
            print("Please enter only hexadecimal digits (0-9, A-F).")

    packets_data = wep_arc4(wep_key_bytes)
    for packet in packets_data:
        packets.append(packet)
        iv.append(packet[:6])
        ciphertext.append(packet[6:])

    print("Generation of ", len(packets), " WEP packets is complete!")

    # Save packets into dataframe
    df = pd.DataFrame({"data": packets, "iv": iv, "ciphertext": ciphertext})

    print()
    print("Dataframe of Packets generated: ")
    print(df)

    df.to_csv("WEP_Packets.csv")
    print("** NOTE: The dataframe is converted to csv and can be found in the 'WEP_Packets.csv' file generated.")

    return df, user_input