"""
Project: NSW Calculator
Author: Shaarang Tanpure
Description:
Encryption Calculator for CSE4NSW Students @ La Trobe University


## Imports from Flask Library
1. Flask class
2. request object - to handle requests from the client
3. jsonify package - to convert our output and send response in json format
4. render_template - to render a particular html file on request if required


## Imports from Flask_cors
1. CORS and cross_origin - to avoid Cross Origin Request Errors

## Misc. Imports
math module - for gcd, pow and other functions
random module - for random number generation

pip install PyCryptodome

pip install pillow

"""

from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS, cross_origin
from werkzeug.utils import secure_filename
import os
from fractions import gcd

"""" Following imports are required for AES Cipher
 ## haslib package in python includes md5 hashing
 ## pip install PyCryptodome to get Cipher pakages 

 """

from hashlib import md5
from base64 import b64decode
from base64 import b64encode
from Crypto import Random
from Crypto.Cipher import DES3
from datetime import datetime
import random


from ecb import ECB
from aes import AESCipher
from des import DES3Cipher
import explanation
from rsa import encrypt_key_generator, extended_euclidean, modulo_pow
#Set upload folder and allowed files

UPLOAD_FOLDER = 'static/img/uploads'
IMG_FOLDER = 'static/img/'
ALLOWED_EXTENTIONS = {'png','jpg','jpeg','bmp'}



# Initialize Flask app
app = Flask(__name__,template_folder='template')

#setting folder permissions
app.secret_key = "Python NSW"


#setting folder permissions
app.secret_key = "Python NSW"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 10*1024*1024         # file size restricted to 10MB

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

#pass Flask initialization to CORS as argument
CORS(app)


@app.errorhandler(404)
def not_found(error = None):
    '''
    Handle 404 HTTP Error
    Generated when request made for a non existing route
    returns a response in json format with custom error message 

    :param error: Initialized to Null
    '''
    message = {
				'status':400,
				'message':'Not Found - '+ request.url,
				}
    resp = jsonify(message)
    resp.status_code = 404
    return resp


@app.route('/',methods=['GET'])
@app.route('/home',methods=['GET'])
def home():
    """
    Route: /home
    HTTP Method: GET
    renders html page calculator.html on request

    """

    return render_template('./index.html')

@app.route('/calculate',methods=['POST'])
def arithmatic_calculator():
    data = request.get_json(force=True)
    text_data = data['data']
    try:
        result = eval(text_data)
    except:
        result = "Exception occured, try again."
    return jsonify({'result': result})

def coprime_generator(lower_limit, upper_limit):
    '''

    Function used to generate co-prime numbers. Takes lower and upper limit arguments

    '''
    result = []
    while(len(result) <= 6):
        try:
            for x in range(lower_limit, upper_limit):
                isPrime = True # initially the isPrime flag is set to true
                for num in range(2, x): # for all numbers in the range of 2 to first number in lower -upper limit range, check if rem is 0. If yes,set flag to false
                    if(x%num == 0):
                        isPrime = False
                if isPrime:
                    result.append(x) # if isPrime is true, append number to result array
        except:
            result.append(0)
    return result


def allowed_file(filename):
    # the function returns a boolean if the file extension matches the allowed types in ALLOWED_EXTENTIONS constant
    return '.' in filename and \
        filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENTIONS

@app.route('/prime', methods=['POST'])
def coprime():
    data = request.get_json(force=True)
    lower_limit = int(data['lower'])
    upper_limit = int(data['higher'])
    result = coprime_generator(lower_limit, upper_limit)
    return jsonify({'result': result})


#calculate rsa
@app.route('/rsagenerate', methods=['POST'])
def rsa():
    data = request.get_json(force=True)
    num1 = int(data['p'])
    num2 = int(data['q'])
    nvalue = num1 * num2
    lvalue = (num1-1) * (num2-1)
    encrypt_keys = encrypt_key_generator(lvalue)
    #random_num = random.randint(1, len(encrypt_keys)) #randomly generate a number between 1 and lenght of encrypt keys
    decrypt_key =  extended_euclidean(encrypt_keys, lvalue)
    #print(lvalue*decrypt_key[1]+encrypt_keys[random_num]*decrypt_key[2])
    data_value = {'nvalue': nvalue, 'lvalue': lvalue, 'encryptkeys': encrypt_keys, 'decryptkeys': decrypt_key}
    return jsonify({'result': data_value})


@app.route('/rsaencrypt', methods=['POST'])
def rsa_encrypt():
    data = request.get_json(force=True)
    result = []
    encrypted_ascii = []
    text = data['text']
    encrypt_key = data['evalue']
    nvalue = data['nvalue']
    for char in text:
        result.append(ord(char))
    
    for r in result:
        encrypted_ascii.append(modulo_pow(r, int(encrypt_key), int(nvalue)))

    return jsonify({'result':{'ascii_value':result,'encrypted_text': encrypted_ascii}})


@app.route('/rsadecrypt', methods=['POST'])
def rsa_decrypt():
    data = request.get_json(force=True)
    decrypted_ascii = []
    decrypted_text = ''
    text = data['text'].split(',')
    decrypt_key = data['dvalue']
    nvalue = data['nvalue']
    for ascii_char in text:
        decrypted_ascii.append(modulo_pow(int(ascii_char), int(decrypt_key), int(nvalue)))
    for char in decrypted_ascii:
        decrypted_text = decrypted_text + chr(char)
    
    return jsonify({'result': {'ascii_value': decrypted_ascii, 'decrypted_text': decrypted_text}})


@app.route('/aesencrypt', methods=['POST'])
def aes_encrypt():
    data = request.get_json(force=True)
    text = data['text']
    secret_key = data['secretkey']
    mode = data['mode']
    print(mode)
    cipher = ''
    try:
        if(mode == 'CBC'):
            cipher = AESCipher(secret_key).cbc_encrypt(text).decode('utf-8')
            cipher = {'ciphertext': cipher}
        elif (mode == 'OFB'):
            cipher = AESCipher(secret_key).ofb_encrypt(text)
        elif(mode == 'CBF'):
            cipher = AESCipher(secret_key).cfb_encrypt(text).decode('utf-8')
        elif(mode == 'CTR'):
            cipher = AESCipher(secret_key).ctr_encrypt(text).decode('utf-8')
    except:
        cipher = 'Error Encountered. Try again!'

    
    return jsonify({'result':{'aescipher':cipher}})

@app.route('/aesdecrypt', methods=['POST'])
def aes_decrypt():
    data = request.get_json(force=True)
    cipher = data['cipher']
    secret_key = data['secretkey']
    mode = data['mode']
    decipher = ''
    try:
        if(mode == 'CBC'):
            decipher = AESCipher(secret_key).cbc_decrypt(cipher).decode('utf-8')
        elif (mode == 'OFB'):
            decipher = AESCipher(secret_key).ofb_decrypt(cipher)
        elif(mode == 'CBF'):
            decipher = AESCipher(secret_key).cfb_decrypt(cipher)
        elif(mode == 'CTR'):
            decipher = AESCipher(secret_key).ctr_decrypt(cipher).decode('utf-8')
    except:
        decipher = 'Incorrect Secret Key. Please enter the same key used for encryption'
    return jsonify({'result':{'aesdecipher':decipher}})


@app.route('/tripledesencrypt', methods=['POST'])
def des_encrypt():
    '''
    Route: /tripledesencrypt
    Method: POST

    gets text to encrypt and secret keys (SK) from the client.
    creates a initialization vector
    Encrypts text using SK1 , decrypts the output from previous step using Sk2 and encrypts output of step2 with SK3

    The result is stored in class varible des_cipher and initialzition vector is stored in class varible des_iv for using 
    them in decryption
    '''
    data = request.get_json(force=True)
    text = data['text'].encode('utf-8')
    secret_key1 = data['secretkey1']
    secret_key2 = data['secretkey2']
    secret_key3 = data['secretkey3']
    iv = Random.new().read(DES3.block_size)
    cipher = ''
    try:
        # encrypting with secret key 1
        cipher1 = DES3Cipher().encrypt(secret_key1, iv, text)

        # decrypt the cipher from previous step with secret key 2
        cipher2 = DES3Cipher().decrypt(secret_key2, iv, cipher1)
        
        # encrypt the cipher from above with secret key 3
        cipher = DES3Cipher().encrypt(secret_key3, iv, cipher2)

    except Exception as e:
        print(e)
        cipher = 'Error Encountered. Try again!. Check if the keys are correct'
    DES3Cipher.des_cipher = cipher
    DES3Cipher.des_iv = iv
    return jsonify({'result':{'descipher':str(cipher)}})

@app.route('/tripledesdecrypt', methods=['POST'])
def triple_des_decrypt():
    '''
    Route: /tripledesdecrypt
    Method: POST

    gets output of encryption and secret keys (SK) from the client.
    Encrypts text using SK1 , decrypts the output from previous step using Sk2 and encrypts output of step2 with SK3

    The result is stored in class varible des_cipher and initialzition vector is stored in class varible des_iv for using 
    them in decryption
    '''
    data = request.get_json(force=True)
    cipher = DES3Cipher.des_cipher
    sk1 = data['secretkey1']
    sk2 = data['secretkey2']
    sk3 = data['secretkey3']
    iv = DES3Cipher.des_iv
    decipher = ''
    try:
        # decipher using sk3 first
        decrypted_text = DES3Cipher().decrypt(sk3, iv, cipher)
        #use that to encrypt using sk2
        
        encrypted_text = DES3Cipher().encrypt(sk2, iv, decrypted_text)

        # decipher encrypted text using sk1
        output = DES3Cipher().decrypt(sk1, iv, encrypted_text)
        
        decipher = output.decode("utf-8","ignore").strip()
    except Exception as e:
        decipher = e
        print(e)
    
    return jsonify({'result':{'plaintext': decipher}})


def convert_to_ecb(mode, filename):
    encryptedFile = ECB().process_image(mode, filename) # call the process_image method of ECB class declared in ecb file, takes the mode of encryption and file as argument
    return encryptedFile



def block_cipher_working(mode):
    data = {}
    if mode == 'CBC':
        data['img'] = IMG_FOLDER+'wo8Bl.png'
        print(data['img'])
        data['title'] = 'CBC Mode Encryption'
        data['explanation'] = explanation.cbc_encyption_explanation()
    else:
        data['img'] = IMG_FOLDER+'ECB_encryption.png'
        data['title'] = 'ECB Mode Encryption'
        data['explanation'] = explanation.ecb_encryption_explanation()

    return data



# route to upload a file
@app.route('/upload', methods=['POST'])
def upload_file():
    filepath = ''
    encrypted_file_relative_path = ''
    try:
        file = request.files['fileUpload'] #get the file sent from form
        mode = request.form['mode'] # the mode of encryption
        if file.filename == '':
            filepath = 'Please select a file'
        if file and allowed_file(file.filename):        #if file is passed in request and the format matches the allowed file formats
            # the file is splited at the extension and we just use the file name, append datetime to it and save it as jpg format
            filename = secure_filename(file.filename.split('.')[0] + ' '+ datetime.now().strftime('%b %d %Y %H:%M:%S') + '.jpg')
            #filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            filepath = app.config['UPLOAD_FOLDER'] + '/'+filename #save it to upload folder
            file.save(filepath)
            file_relative_path = filepath 
            encrypted_file_relative_path = convert_to_ecb(mode, filepath)
    except Exception as e:
        filepath = e

    return jsonify({'result':{'originalfile':file_relative_path, 'encryptedfile': encrypted_file_relative_path, 'explanation':block_cipher_working(mode) }})



if __name__ == '__main__':
  app.run(host='0.0.0.0',debug=True)
