''' This file contains all helper methods for RSA encryption '''
from fractions import gcd



def encrypt_key_generator(phi):
    '''
    Function used to generate encryption key for RSA encryption. Returns a number whose gcd is 1 with Lvalue else returns 0

    '''
    for x in range(2, phi):
        if(gcd(x, phi) == 1):
            return x
    return 0



def extended_euclidean(a, b):
    '''x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y'''
    x = 0
    y = 1
    lx = 1
    ly = 0
    oa = a  # Remember original a/b to remove
    ob = b  # negative values from return results
    while b != 0:
        q = a // b
        (a, b) = (b, a % b)
        (x, lx) = ((lx - (q * x)), x)
        (y, ly) = ((ly - (q * y)), y)
    if lx < 0:
        lx += ob  # If neg wrap modulo orignal b
    if ly < 0:
        ly += oa  # If neg wrap modulo orignal a
    # return a , lx, ly  # Return only positive values
    return lx

def modulo_pow(base, exponent, modulo):
    if modulo == 1:
        return 0
    result = 1
    base = base % modulo
    while(exponent > 0):
        if(exponent % 2 == 1):
            result = (result * base) % modulo
        exponent = exponent >> 1
        base = (base * base) % modulo
    return result