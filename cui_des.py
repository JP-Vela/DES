import des_constants_permutation_tables as tables
import des_constants_sbox_tables as sbox_tables
import des_constants_subkey_tables as subkey_tables


def _hex_print(block:bytes):
    print(''.join(hex(x)[2:] for x in block))

def _nsplit(data, split_size=64):
    """Split list every split_size element"""

    splitted = []

    for i in range(0,len(data), split_size):
        splitted.append(data[i:i+split_size])

    return splitted

def _rem_padding(message):
    """Take the byte at the end and remove that many bytes"""
    last_bit = message[-1]
    message = message[:len(message)-last_bit]
    return message

def _add_padding(message):
    """Add padding if the byte string is less than 8 bytes long"""
    pad_size = 8 - len(message)%8
    message += bytes([pad_size]*pad_size)
    return message


# Completely ChatGPT generated
def _bytes_to_bit_array(byte_string):
    """Convert each byte to an 8-bit binary representation"""
    bit_array = []
    for byte in byte_string:
        # Format the byte as a binary string, padded with leading zeros to ensure it's 8 bits
        bits = format(byte, '08b')
        # Convert each character in the string 'bits' into an integer (0 or 1) and append to the bit_array
        bit_array.extend([int(bit) for bit in bits])
    
    return bit_array

# Completely ChatGPT generated
def _bit_array_to_bytes(bit_array):
    """Ensure the length of bit_array is a multiple of 8"""
    if len(bit_array) % 8 != 0:
        raise ValueError("The length of the bit array should be a multiple of 8.")

    byte_string = bytearray()
    
    # Iterate over the bit array in chunks of 8 bits
    for i in range(0, len(bit_array), 8):
        byte = bit_array[i:i+8]  # Get 8 bits
        # Convert 8 bits into a byte
        byte_value = int(''.join(str(bit) for bit in byte), 2)
        # Append the byte to the byte string
        byte_string.append(byte_value)
    
    return bytes(byte_string)

# Implemenation of DES algorithm
class DES:
    def __init__(self, mode='ECB', key=''):
        self.mode = mode
        self.key = key
    
    def _permute(self, block, table):
        """Transposition of bits based on the DES tables"""
        output = []
        for i in range(len(table)):
                output.append(block[table[i]])
            
        return output

    def _lshift(self, sequence, n):
        """Move a list n places to the left and wrap around"""
        shifted = sequence[n:]+sequence[:n]
        return shifted

    def _xor(self, x, y):
        """Bitwise XOR over two arrays of bits"""
        output = []

        for b1, b2 in zip(x,y):
            output.append(b1^b2)

        return output


    def _substitute(self, bit_array:list):
        """SBOX substitution
        first and last bits make the row number
        middle 4 bits make the column number"""
        chunks = _nsplit(bit_array, 6)
        outputs = ""
        sboxes = sbox_tables._S_BOXES

        for i in range(len(chunks)):

            chunk = chunks[i]
            first_bit = str(chunk[0])
            last_bit = str(chunk[-1])

            middle_bits = ''.join([str(n) for n in chunk[1:-1]]) # Join the middle 4 bits together as strings

            # Convert binary to decimal (int)
            row = int(first_bit+last_bit, 2)
            col = int(middle_bits, 2)

            output_val = sboxes[i][row][col] # Get the value at the row and column in the current SBOX
            output_val = bin(output_val)[2:] # Convert decimal to binary and remove the '0b'
            output_val = (4-len(output_val))*'0'+output_val # Add '0' as padding to make them all 4 bits long
            outputs += output_val

        return [int(i) for i in outputs]
        

    def _generate_subkeys(self, encryption_key:bytes):
        """Generate 16 subkeys from the 64 bit key"""
        subkeys = []

        # 64 bit to 56 bit key
        key_as_bit_array = _bytes_to_bit_array(encryption_key)
        key_56b = self._permute(key_as_bit_array, subkey_tables._KEY_PERMUTATION1)
        lhs = key_56b[:28] # Left hand side
        rhs = key_56b[28:] # Right hand side

        for i in range(16):
            shift_ammount = subkey_tables._KEY_SHIFT[i]

            lhs = self._lshift(lhs, shift_ammount)
            rhs = self._lshift(rhs, shift_ammount)

            subkey = self._permute(lhs+rhs, subkey_tables._KEY_PERMUTATION2)
            subkeys.append(subkey)


        return subkeys


    def _functionF(self, R, subkey):
        temp = self._permute(R, tables._EXPAND)
        temp = self._xor(temp, subkey)
        temp = self._substitute(temp) # 48 bit to 32 bit
        temp = self._permute(temp, tables._SBOX_PERM)
        return temp


    def _crypt_block(self, block, subkeys):
        """Encrypt 64 bit block using 16 subkeys"""
        block = self._permute(block, tables._INIT_PERMUTATION) # Inital permutation
        lhs, rhs = block[:32], block[32:]

        for i in range(16):
            temp = self._functionF(rhs, subkeys[i])
            temp = self._xor(temp, lhs)
            lhs = rhs
            rhs = temp
        

        block = self._permute(rhs+lhs, tables._FINAL_PERMUTATION) # Swapping lhs & rhs is important for some reason
        return block



    def _encrypt_ecb(self, data, subkeys):
        """Encrypt bytes using DES Electronic Code Book method"""
        data = _add_padding(data)
        data = _bytes_to_bit_array(data)

        ct = []
        for block in _nsplit(data, 64):
            ct += self._crypt_block(block, subkeys)

        ct = _bit_array_to_bytes(ct)

        return ct
    
    def _decrypt_ecb(self, data, subkeys):
        """Decrypt bytes using DES Electronic Code Book method"""
        data = _bytes_to_bit_array(data)

        ct = []
        for block in _nsplit(data, 64):
            db = self._crypt_block(block, subkeys)
            ct += db

        ct = _bit_array_to_bytes(ct)
        ct = _rem_padding(ct)
        return ct
    
    def _encrypt_cbc(self, data, subkeys, iv):
        """Encrypt bytes using DES Cipher Block Chaining method"""
        data = _add_padding(data)
        data = _bytes_to_bit_array(data)
        iv = _bytes_to_bit_array(iv)

        ct = []
        for block in _nsplit(data, 64):
            block = self._xor(block,iv)
            iv = self._crypt_block(block, subkeys)
            ct += iv

        ct = _bit_array_to_bytes(ct)

        return ct
    
    def _decrypt_cbc(self, data, subkeys, iv):
        """Decrypt bytes using DES Cipher Block Chaining method"""
        data = _bytes_to_bit_array(data)
        iv = _bytes_to_bit_array(iv)

        ct = []
        for block in _nsplit(data, 64):
            temp = block
            block = self._crypt_block(block, subkeys)
            block = self._xor(block, iv)
            iv = temp
            ct += block

        ct = _bit_array_to_bytes(ct)
        ct = _rem_padding(ct)
        return ct


    def _encrypt_ofb(self, data, subkeys, iv):
        """Encrypt bytes using DES Output Feedback method"""
        data = _bytes_to_bit_array(data)
        iv = _bytes_to_bit_array(iv)

        ct = []
        for block in _nsplit(data, 64):
            temp_ct = self._crypt_block(iv, subkeys)
            iv = temp_ct
            temp_ct = self._xor(block, temp_ct)
            ct += temp_ct

        ct = _bit_array_to_bytes(ct)

        return ct
        
    def _decrypt_ofb(self, data, subkeys, iv):
        """Decrypt bytes using DES Output Feedback method"""
        subkeys.reverse()
        return self._encrypt_ofb(data, subkeys, iv)



    def encrypt(self, data, key=None, iv=None, cc=False):
        """ Encrypts plaintext data with DES (Data Encryption Standard).

            Parameters:
            data (bytes): input data to be encrypted
            key (bytes):  64-bit key used for DES encryption
            iv (bytes): 64-bit initialization vector used in DES CBC and OFB encryption
            cc (bool): boolean determining whether to return a byte string, or string in the CyberChef formated hex digits

            Returns:
            An encrypted byte string of equal length to the original data
        """

        if key==None:
            key = self.key
        
        if iv == None and self.mode != 'ECB':
            iv = b'\x00'*8

        subkeys = self._generate_subkeys(key)

        ct = None

        if self.mode == 'ECB':
            ct = self._encrypt_ecb(data, subkeys)
        elif self.mode == 'CBC':
            ct = self._encrypt_cbc(data, subkeys, iv)
        elif self.mode == 'OFB':
            ct = self._encrypt_ofb(data, subkeys, iv)
        else:
            raise ValueError()
    
        # Add leading 0s padding because hex(i) removes the leading zeroes while CyberChef does not
        if cc:
            ct = ''.join(f"{int(i):#0{4}x}"[2:] for i in ct)

        return ct


    # Remove padding and reverse subkeys
    def decrypt(self, data, key=None, iv=None):
        """ Decrypts ciphertext data with DES (Data Encryption Standard).

            Parameters:
            data (bytes): input data to be encrypted
            key (bytes):  64-bit key used for DES decryption
            iv (bytes): 64-bit initialization vector used in DES CBC and OFB decryption

            Returns:
            An encrypted byte string of equal length to the original data
        """
        if key==None:
            key = self.key
            
        subkeys = self._generate_subkeys(key)
        subkeys.reverse()

        if self.mode == 'ECB':
            return self._decrypt_ecb(data, subkeys)

        elif self.mode == 'CBC':
            return self._decrypt_cbc(data, subkeys, iv)

        elif self.mode == 'OFB':
            return self._decrypt_ofb(data, subkeys, iv)





# TRIPLE DES
class T_DES(DES):
    def __init__(self, mode='ECB', key=''):
        self.mode = mode
        self.key = key

    def _split_keys(self, key):
        """Split 192 bit key into 3 64 bit keys"""
        return _nsplit(key, 8) # split every 8 bytes (64 bits)

    def _encrypt_ecb(self, data, key):
        """Encrypt bytes using DES Electronic Code Book method"""
        splitted_keys = self._split_keys(key)
        subkeys1 = self._generate_subkeys(splitted_keys[0])
        subkeys2 = self._generate_subkeys(splitted_keys[1])
        subkeys3 = self._generate_subkeys(splitted_keys[2])

        subkeys2.reverse()

        data = _add_padding(data)
        data = _bytes_to_bit_array(data)

        ct = []
        for block in _nsplit(data, 64):
            ct_block = self._crypt_block(block, subkeys1)
            ct_block = self._crypt_block(ct_block, subkeys2)
            ct_block = self._crypt_block(ct_block, subkeys3)
            ct += ct_block

        ct = _bit_array_to_bytes(ct)

        return ct
    
    def _decrypt_ecb(self, data, key=None):
        """Decrypt bytes using DES Electronic Code Book method"""
        if key==None:
            key = self.key

        # return self.decrypt(data, key)
        splitted_keys = self._split_keys(key)
        subkeys1 = self._generate_subkeys(splitted_keys[0])
        subkeys2 = self._generate_subkeys(splitted_keys[1])
        subkeys3 = self._generate_subkeys(splitted_keys[2])
        subkeys1.reverse()
        subkeys3.reverse()

        data = _bytes_to_bit_array(data)

        ct = []
        for block in _nsplit(data, 64):
            db = self._crypt_block(block, subkeys3)
            db = self._crypt_block(db, subkeys2)
            db = self._crypt_block(db, subkeys1)
            ct += db

        ct = _bit_array_to_bytes(ct)
        ct = _rem_padding(ct)
        return ct
    

    def _encrypt_cbc(self, data, key, iv):
        """Encrypt bytes using DES Cipher Block Chaining method"""
        splitted_keys = self._split_keys(key)

        subkeys1 = self._generate_subkeys(splitted_keys[0])
        subkeys2 = self._generate_subkeys(splitted_keys[1])
        subkeys2.reverse()
        subkeys3 = self._generate_subkeys(splitted_keys[2])

        data = _add_padding(data)
        data = _bytes_to_bit_array(data)
        iv = _bytes_to_bit_array(iv)

        ct = []
        for block in _nsplit(data, 64):
            block = self._xor(block,iv)
            iv = self._crypt_block(block, subkeys1)
            iv = self._crypt_block(iv, subkeys2)
            iv = self._crypt_block(iv, subkeys3)
            ct += iv

        ct = _bit_array_to_bytes(ct)

        return ct
    
    def _decrypt_cbc(self, data, key, iv):
        """Decrypt bytes using DES Cipher Block Chaining method"""
        splitted_keys = self._split_keys(key)

        subkeys1 = self._generate_subkeys(splitted_keys[0])
        subkeys2 = self._generate_subkeys(splitted_keys[1])
        subkeys3 = self._generate_subkeys(splitted_keys[2])
        subkeys1.reverse()
        subkeys3.reverse()

        data = _bytes_to_bit_array(data)
        iv = _bytes_to_bit_array(iv)
        ct = []
        for block in _nsplit(data, 64):
            temp = block
            block = self._crypt_block(block, subkeys3)
            block = self._crypt_block(block, subkeys2)
            block = self._crypt_block(block, subkeys1)
            block = self._xor(block, iv)
            iv = temp
            ct += block

        ct = _bit_array_to_bytes(ct)
        ct = _rem_padding(ct)
        return ct


    def _encrypt_ofb(self, data, key, iv):
        """Encrypt bytes using DES Output Feedback method"""
        splitted_keys = self._split_keys(key)

        subkeys1 = self._generate_subkeys(splitted_keys[0])
        subkeys2 = self._generate_subkeys(splitted_keys[1])
        subkeys2.reverse()
        subkeys3 = self._generate_subkeys(splitted_keys[2])

        data = _bytes_to_bit_array(data)
        iv = _bytes_to_bit_array(iv)

        ct = []
        for block in _nsplit(data, 64):
            temp_ct = self._crypt_block(iv, subkeys1)
            temp_ct = self._crypt_block(temp_ct, subkeys2)
            temp_ct = self._crypt_block(temp_ct, subkeys3)
            iv = temp_ct
            temp_ct = self._xor(block, temp_ct)
            ct += temp_ct

        ct = _bit_array_to_bytes(ct)

        return ct
        
    
    def _decrypt_ofb(self, data, key, iv):
        """Decrypt bytes using DES Output Feedback method"""
        return self._encrypt_ofb(data, key, iv)

    def encrypt(self, data, key=None, iv=None, cc=False):
        """ Encrypts plaintext data with DES (Data Encryption Standard).

            Parameters:
            data (bytes): input data to be encrypted
            key (bytes):  192-bit key used for DES encryption
            iv (bytes): 64-bit initialization vector used in DES CBC and OFB encryption
            cc (bool): boolean determining whether to return a byte string, or string in the CyberChef formated hex digits

            Returns:
            An encrypted byte string of equal length to the original data
        """
        
        if key == None:
            key = self.key

        if iv == None and self.mode != 'ECB':
            iv = b'\x00'*8

        ct = None

        if self.mode == 'ECB':
            ct = self._encrypt_ecb(data, key)
        elif self.mode == 'CBC':
            ct = self._encrypt_cbc(data, key, iv)
        elif self.mode == 'OFB':
            ct = self._encrypt_ofb(data, key, iv)
        else:
            raise ValueError()
        
                # Add leading 0s padding because hex(i) removes the leading zeroes while CyberChef does not
        if cc:
            ct = ''.join(f"{int(i):#0{4}x}"[2:] for i in ct)
        return ct
    
    def decrypt(self, data, key=None, iv=None):
        """ Decrypts ciphertext data with DES (Data Encryption Standard).

            Parameters:
            data (bytes): input data to be encrypted
            key (bytes):  192-bit key used for DES decryption
            iv (bytes): 64-bit initialization vector used in DES CBC and OFB decryption

            Returns:
            An encrypted byte string of equal length to the original data
        """
        if key == None:
            key = self.key

        if iv == None and self.mode != 'ECB':
            iv = b'\x00'*8

        if self.mode == 'ECB':
            return self._decrypt_ecb(data, key)
        elif self.mode == 'CBC':
            return self._decrypt_cbc(data, key, iv)
        elif self.mode == 'OFB':
            return self._decrypt_ofb(data, key, iv)
        else:
            raise ValueError()


    
if __name__ == '__main__':
    tdes = T_DES(mode='ECB', key=b'anappleadaykeepsthedocto')
    original = b'hello there'
    ct = tdes.encrypt(original)
    
    print(f"Original Text: {original}")
    print(f"Cypher Text: {ct}")
    print(f"Decrypted text: {tdes.decrypt(ct)}")