from hashlib import md5
from base64 import b64decode
from base64 import b64encode
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class AESCipher:
    # Class Constructor
    # hash the secret key using MD5 hasing
    def __init__(self, key):
        self.key = md5(key.encode('utf8')).digest()

    # Encrpyt - gets data passed to it. Randomly generates Block size and then uses CBC mode to encrypt the text and the key
    def cbc_encrypt(self, data):
        iv = get_random_bytes(AES.block_size)
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + self.cipher.encrypt(pad(data.encode('utf-8'), 
            AES.block_size)))

    # Decrypt - gets data passed to it. Uses secret key to decrypt the cipher text
    def cbc_decrypt(self, data):
        raw = b64decode(data)
        self.cipher = AES.new(self.key, AES.MODE_CBC, raw[:AES.block_size])
        return unpad(self.cipher.decrypt(raw[AES.block_size:]), AES.block_size)
    
    def cfb_encrypt(self, data):
        iv = get_random_bytes(AES.block_size)
        self.cipher = AES.new(self.key, AES.MODE_CFB, iv)
        ct_bytes = self.cipher.encrypt(data)
        print(ct_bytes)
        initialization_vector = b64encode(self.cipher.iv).decode('utf-8')
        print(initialization_vector)
        cipher_text = b64encode(ct_bytes).decode('utf-8')
        print(cipher_text)
        result = {'iv': initialization_vector, 'cipher': cipher_text}
        return result


    def cfb_decrypt(self, data):
        result = ''
        try:
            json_data = json.loads(data)
            initialization_vector = b64decode(json_data['iv'])
            cipher_text = b64decode(json_data['cipher'])
            cipher = AES.new(self.key, AES.MODE_CFB, iv=initialization_vector)
            original_msg = cipher.decrypt(cipher_text)
            result = original_msg
            print(result)
        except:
        	result = 'Exception occured while decrypting'
        return result
    
    '''
    CTR Mode
    A counter block is exactly as long as the cipher block size (e.g. 16 bytes for AES). It consist of the concatenation of two pieces:

    - a fixed nonce, set at initialization.
    - a variable counter, which gets increased by 1 for any subsequent counter block. The counter is big endian encoded.

    '''
    def ctr_encrypt(self, data):
        print(data)
        #iv = get_random_bytes(AES.block_size)
        self.cipher = AES.new(self.key, AES.MODE_CTR)
        ct_bytes = self.cipher.encrypt(data.encode('utf-8'))
        print('AES')
        print(ct_bytes)
        nonce = b64encode(self.cipher.nonce).decode('utf-8')
        cipher_text = b64encode(ct_bytes).decode('utf-8')
        result = {'nonce': nonce, 'cipher': cipher_text}
        print(result)
        return result
    
    def ctr_decrypt(self, data):
        result = ''
        try:
            json_input = data
            nonce = b64decode(json_input['nonce'])
            cipher_text = b64decode(json_input['cipher'])
            self.cipher =  AES.new(self.key, AES.MODE_CTR, nonce=nonce)
            message = self.cipher.decrypt(cipher_text)
            result = message
        except Exception as e:
            result = e
        
        return result
    
    '''
    Output FeedBack, defined in NIST SP 800-38A, section 6.4. 
    It is another mode that leads to a stream cipher. 
    Each byte of plaintext is XOR-ed with a byte taken from a keystream: the result is the ciphertext. The keystream is obtained by recursively encrypting the Initialization Vector.

    '''

    def ofb_encrypt(self, data):
       result = ''
       self.cipher = AES.new(self.key, AES.MODE_OFB)
       print(self.cipher.iv)
       cipher_text = b64encode(self.cipher.encrypt(data.encode('utf-8')))
       initialization_vector = b64encode(self.cipher.iv).decode('utf-8')
       result = {'iv': initialization_vector, 'ciphertext': cipher_text}
       print(str(result))
       return result
    

    def ofb_decrypt(self, data):
        result = ''
        try:
            json_input = data
            iv = json_input['iv']
            ct = json_input['ciphertext']
            cipher = AES.new(self.key, AES.MODE_OFB, iv=iv)
            plain_text = cipher.decrypt(ct)
            result = plain_text
        except (ValueError, KeyError):
            result = 'Error in decrypting message!'
        return result