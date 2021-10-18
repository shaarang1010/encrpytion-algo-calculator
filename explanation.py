import os
import sys

def cbc_encyption_explanation():
    return ("Cipher block chaining (CBC) is a mode of operation for a block cipher (one in which a sequence of bits are encrypted as a single unit or block with a cipher key applied to the entire block). Cipher block chaining uses what is known as an initialization vector (IV) of a certain length."
    +" One of its key characteristics is that it uses a chaining mechanism that causes the decryption of a block of ciphertext to depend on all the preceding ciphertext blocks. "
    +"As a result, the entire validity of all preceding blocks is contained in the immediately previous ciphertext block. A single bit error in a ciphertext block affects the decryption of all subsequent blocks. Rearrangement of the order of the ciphertext blocks causes decryption to become corrupted. Basically, in cipher block chaining, each plaintext block is XORed (see XOR) with the immediately previous ciphertext block, and then encrypted.Identical ciphertext blocks can only result if the same plaintext block is encrypted using both the same key and the initialization vector, and if the ciphertext block order is not changed. \nIt has the advantage over the Electronic Code Book mode in that the XOR'ing process hides plaintext patterns.Ideally, the initialization vector should be different for any two messages encrypted with the same key. \nThough the initialization vector need not be secret, some applications may find this desirable.")


def ecb_encryption_explanation():
    return ("Electronic Code Book (ECB) is a mode of operation for a block cipher, with the characteristic that each possible block of plaintext has a defined corresponding ciphertext value and vice versa. In other words, the same plaintext value will always result in the same ciphertext value. Electronic Code Book is used when a volume of plaintext is separated into several blocks of data, each of which is then encrypted independently of other blocks."
    +" \n In fact, Electronic Code Book has the ability to support a separate encryption key for each block type."
    +"\nHowever, Electronic Code Book is not a good system to use with small block sizes (for example, smaller than 40 bits) and identical encryption modes."
    +"\nThis is because some words and phrases may be reused often enough so that the same repetitive part-blocks of ciphertext can emerge, laying the groundwork for a codebook attack where the plaintext patterns are fairly obvious."
    +"\nHowever, security may be improved if random pad bits are added to each block. On the other hand, 64-bit or larger blocks should contain enough unique characteristics (entropy) to make a codebook attack unlikely to succeed.")