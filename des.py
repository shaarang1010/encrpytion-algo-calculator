from Crypto.Cipher import DES3
from Crypto import Random


class DES3Cipher:
    des_cipher = ''
    des_iv = ''
    # Class Constructor
    # hash the secret key using MD5 hasing
    def __init__(self):
        self.iv = Random.new().read(DES3.block_size) #DES3.block_size==8
    
    def encrypt(self, key, iv, data):
        # Initialize DES3 - 
        cipher_encrypt = DES3.new(key, DES3.MODE_OFB, iv)
        plaintext = data
        encrypted_text = cipher_encrypt.encrypt(plaintext)
        return encrypted_text
    
    def decrypt(self, key, iv, data):
        cipher_decrypt = DES3.new(key, DES3.MODE_OFB, iv)
        plaintext = cipher_decrypt.decrypt(data)
        #print(plaintext)
        return plaintext