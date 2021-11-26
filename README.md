# CZ4010 WEP Cracking
This GitHub repository is for the module CZ4010 Applied Cryptography, and it is for Project Topic #6: Demonstration of WEP Password Cracking.

# 1. Motivation
Wired Equivalent Privacy, also known as WEP, was a well recognised Wi-Fi security standard during the early 2000s. However, over time, many people discovered multiple weaknesses WEP had, and exploited the weakness to launch attacks on WEP. There are now various known attacks that are successful, and have threatened the WEP security standard. This caused many to stop using WEP and use its more secure alternatives, such as Wi-Fi Protected Access (WPA), WPA2, and many more.

# 2. Research
## 2.1. Wired Equivalent Privacy (WEP)
WEP takes in a 40-bit (5 bytes, 10 hexadecimal digits) or 104-bits (13 bytes, 26 hexadecimal digits) key or password, and generates a 24-bit IV (3 bytes). The most common form of the session key of WEP is as follows:
```
session_key = IV || WEP
```

The session key (or seed) is then used as an input into the ARC4 stream cipher, to produce a keystream that is of the same length as the plaintext that is to be encrypted. The plaintext is then XORed with the session key to form the ciphertext as shown below:
```
ciphertext  = plaintext XOR keystream
```

The ciphertext is then sent along with the IV as a data packet as follows:
```
data_packet = IV || ciphertext
```

### 2.1.1. Rivest Cipher 4 (RC4/ARC4) in WEP
Firstly, the ARC4 stream cipher initialises the S-box using the session key and puts it through the KSA to generate an initial state of the S-box. The KSA performs swaps between computed indexes of the S-box.

Then, using the initialised S-box, the Pseudo-Random Generation Algorithm (PRGA) scrambles it further, and every iteration produces a byte of the keystream. The PRGA also performs swaps between computed indexes of the S-box. Each byte of the generated keystream is then XORed with each byte of the plaintext to form the ciphertext, as mentioned previously.

## 2.2. Attacks on WEP
There are many known attacks on WEP. The simplest form is a brute force attack, where the attacker exhausts all possible values of IV (2^24), which can be done within hours. Most of them leverage on the weakness of the Rivest Cipher 4 (ARC4 or RC4), which is utilised in WEP to encrypt the WEP key. Such attacks may include the Klein’s attack and the Fluhrer, Mantin and Shamir (FMS) attack. 

### 2.2.1. Fluhrer, Mantin and Shamir (FMS) attack
The FMS attack allows attackers to derive the key from a numerous amount of messages that are encrypted with ARC4 Stream Cipher. It specifically exploits the weakness in the PRGA of ARC4.

Before the start of any scrambling, the attacker can actually derive the first byte of the keystream, as the first byte of the plaintext is usually always ‘0xAA’, which is the value of the SNAP header. We will use the value of the first byte of the keystream later on. The first byte of the keystream is then obtained as follows:
```
keystream_first_byte = 0xAA XOR ciphertext_first_byte
```

There are particular IVs, which are deemed as weak IVs, that allow attackers to possibly derive the (M+1)th byte of the WEP key if they have the first byte of the keystream and the 0th to Mth bytes of the key.  This exploit is a result of one of the weaknesses of the PRGA in ARC4.

# 3. Design
We will create our own mock WEP protocol, as we face difficulties in extracting actual WEP packets due to hardware constraints.

We will be designing our WEP cracking program based on the FMS attack on WEP, specifically targeting the ARC4, as it provides us with a proper guess for the WEP key, instead of other methods where frequency analysis is required, and many manual adjustments are required, which is not ideal.

## 3.1. WEP Encryption
There are 5 files involved in the WEP encryption.<br/>
1. arc4.py<br/>
This file contains the code for the ARC4 KSA (arc4_ksa) and PRGA (arc4_prga) implementation, as well as a bytewise XOR function (byte_xor).<br/><br/>
2. packet.py<br/>
This file contains the function (create_packets) for collating suitable WEP packets to output as WEP_Packets.csv, and is also where the program asks the user to input the WEP key.<br/><br/>
3. wep.py<br/>
This file contains the function (wep_arc4) for generating WEP packets with IVs in the suitable form for FMS attack. It also contains a function to generate a random plaintext (get_plaintext) and another function to generate all possible IVs in the suitable format (generate_ivs).<br/><br/>
4. sentences.txt<br/>
This file contains a list of sentences where a sentence can be randomly chosen and used as a plaintext for WEP encryption.<br/><br/>
5. WEP_Packets.csv<br/>
This file contains all the generated WEP packets from the program. The data in this particular CSV file is for the key ‘ABCDEF12345678901234567890’, and the plaintexts are randomly selected from the available sentences in sentences.txt. This CSV file will be overwritten every time the program runs.<br/><br/>
It has 4 columns, which are row number, data, iv, and ciphertext.<br/><br/>
- row number is the index of each row in the dataframe.
- data is the actual WEP packet data transmitted.
- iv is the first 6 hexadecimal digits of the data.
- ciphertext is the remaining digits of the data, excluding the first 6 hexadecimal digits.

## 3.2. WEP Cracking
There is 1 file involved in the WEP Cracking.<br/>
1. wep_cracking.py<br/>
This file contains the code for the function (wep_cracking) for conducting the FMS attack and cracking the code.

# 4. Development
The FMS attack focuses on collecting packets with IVs in the particular form: (A + 3, N − 1, X).
- A is a value that varies from 0 to (length of WEP key - 1), where the length of the WEP key is in terms of the number of bytes.
- N is the keyspace a byte can represent, which is 256 (in base 10).
- X is a value from 0 to 255 inclusive.

After collecting enough WEP packets which contain IVs in the form mentioned above, the attacker iterates through each of such packets. The first IV of such form is (3,255,0)

To start off, the attacker initialises the S-Box through the KSA using just the first 3 bytes of the session key, which is the 3 bytes of the IV, and does the first 3 iterations of the KSA. From this state of the S-box, the attacker can generate a guess of the value of the next byte of the session key(e.g. 4th byte of session key) using the following formula:
```
# i = 3 for this instance
session_key_next_byte = keystream_first_byte - j - s_box[i]
```
This provides a potential value of the next byte of the session key. Then, the attacker needs to repeat this for all packets that are suitable for this attack, and then find the most repeated potential value of the next byte of the session key. This value will then be taken as the confirmed guess for the next byte of the session key.
 
The attacker then repeats the same process, doing 4 iterations of the KSA using the 4 ‘known’ bytes of the session key to get the confirmed guess for the fifth byte of the session key, and so on, until all bytes of the session key have a value.
 
After getting all potential values of the bytes of the session key (in decimal), the attacker then omits the first 3 bytes to get the potential WEP key. The attacker then has to convert each value of the bytes to hexadecimal and then compare with the actual WEP key, which is in hexadecimal. If the potential key guess matches the actual WEP key, the attacker successfully cracked the WEP key.

# 5. Use of the code
1. To install the required dependencies, run the following command in the root directory:
```
pip install -r requirements.txt
```
2. To start the program, run the following command in the root directory:
```
python wep_cracking.py
```
3. The user will need to provide 2 inputs during the program:
- Type the WEP key you want to crack using this program and press ‘Enter’ at the start of the program.
- Press ‘Enter’ when the generation of packets is complete.
4. The program will print to the console a guess of the WEP key it derived from the FMS attack, and will check whether the WEP key guess is correct. If the guess is correct, the program prints to the console a success message, else, it prints a failure message.
