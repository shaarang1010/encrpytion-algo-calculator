from PIL import Image
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import random
import string
import os

FOLDER_LOCATION  = 'static/img/encrypted'


# create encrypted folder if not exists
if not os.path.exists(FOLDER_LOCATION):
    os.makedirs(FOLDER_LOCATION)

# This method generates random characters for the specified size
def generate_random_characters(number):
    random_characters = ''.join(random.SystemRandom().choice(string.ascii_lowercase + string.digits) for _ in range(number))
    return random_characters

class ECB:
    key = generate_random_characters(16)
    img_format = 'BMP'
    
    # AES requires that plaintexts be a multiple of 16, so we have to pad the data
    @staticmethod
    def pad(data):
        return data + b"\x00"*(16-len(data)%16) 
     
    # Maps the RGB 
    @staticmethod
    def convert_to_RGB(data):
        pixels = None
        print('converting to RGB')
        try:
            r, g, b = tuple(map(lambda d: [data[i] for i in range(0,len(data)) if i % 3 == d], [0, 1, 2]))
            pixels = tuple(zip(r,g,b))
        except Exception as e :
            pixels = e
        return pixels
            
    @classmethod
    def process_image(cls, mode, filename):
        # Opens image and converts it to RGB format for PIL
        print("in process image")
        im = Image.open(filename)

        data = im.convert("RGB").tobytes()

        # Since we will pad the data to satisfy AES's multiple-of-16 requirement, we will store the original data length and "unpad" it later.
        original = len(data)
        # Encrypts using desired AES mode (we'll set it to CBC by default)
        if mode == 'CBC':
            new = cls.convert_to_RGB(cls.aes_cbc_encrypt(cls.key.encode('utf-8'), cls.pad(data))[:original])
        else:
            new = cls.convert_to_RGB(cls.aes_ecb_encrypt(cls.key.encode('utf-8'), cls.pad(data))[:original])

        # Create a new PIL Image object and save the old image data into the new image.
        im2 = Image.new(im.mode, im.size)
        im2.putdata(new)
        # we want to get to randomize file name for security 
        randomize_file_name = generate_random_characters(8)
        filename_out = FOLDER_LOCATION + '/'+'_'+randomize_file_name 
         
        #Save image
        im2.save(filename_out+"."+cls.img_format, cls.img_format)
        filename_out = filename_out+"."+cls.img_format
        return filename_out
     
    # CBC
    @staticmethod
    def aes_cbc_encrypt(key, data, mode=AES.MODE_CBC):
        IV = get_random_bytes(AES.block_size)
        try:  
            aes = AES.new(key, mode, IV)
        except Exception as e:
            print(e)
        #print(aes)
        new_data = aes.encrypt(data)
        #print(new_data)
        return new_data
    # ECB
    
    @staticmethod
    def aes_ecb_encrypt(key, data, mode=AES.MODE_ECB):
        aes = AES.new(key, mode)
        new_data = aes.encrypt(data)
        return new_data
     
'''if __name__ == '__main__': 
    process_image(filename)'''
