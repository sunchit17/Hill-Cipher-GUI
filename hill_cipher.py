import argparse
import math
import numpy as np

def check_key(key):
    """
    Argument: key to encrypt-decrypt
    Checks if the key length is a perfect square
    """
    key_length = len(key)
    if (math.sqrt(key_length) - int(math.sqrt(key_length))) != 0:
        raise ValueError("Please enter a valid key!")

def pad_message(message, n):
    """
    Argument: message, block size - n
    Returns padded message
    """
    mes_len = len(message)
    if (mes_len % n) != 0:
        pad_len = n - (mes_len % n)
        message_padded = message + pad_len*'z'
        return message_padded
    return message

def convert_to_num(l):
    """
    Argument: String
    Returns a list of corresponding numbers. Eg, abz -> [0, 1, 25]
    """
    return [(ord(c)-97) for c in l]

def convert_msg(message, n):
    """
    Argument: Message (String), block length n
    Converts a message into corresponding numbers and returns a list of the blocks of message.
    """
    mes = convert_to_num(message)
    mes_blocks = []
    for i in range(int(len(message)/n)):
        temp = np.array(mes[n*i:(n*i)+n])
        temp = np.reshape(temp, (n, 1))
        mes_blocks.append(temp)
    return np.array(mes_blocks)

def encrypt(k, m):
    """
    Argument: key matrix k, list of message blocks m
    Returns encrypted message
    """
    msg = []
    for block in m:
        temp = k.dot(block) % 26 + 97
        msg.append(temp)
    msg = np.array(msg).flatten()
    enc_msg = [chr(n) for n in msg]
    return "".join(enc_msg)

def decrypt(k, m):
    """
    Argument: key matrix k, list of encrypted message blocks m
    Returns decrypted message
    """
    k_inv = invert_key(k)
    msg = []
    for block in m:
        temp = k_inv.dot(block) % 26 + 97
        msg.append(temp)
    msg = np.array(msg).flatten()
    dec_msg = [chr(int(n)) for n in msg]
    return "".join(dec_msg)


def invert_key(k):
    """
    Argument: key matrix
    Returns the inverted key matrix accouding to Hill Cipher algorithm.
    """
    det = int(np.round(np.linalg.det(k)))
    det_inv = multiplicative_inverse(det % 26)
    k_inv = det_inv * np.round(det*np.linalg.inv(k)).astype(int) % 26
    return k_inv

def multiplicative_inverse(det):
    """
    Argument: determinant d, number
    Returnms d_inv according to (d*d_inv = 1 mod 26)
    """
    mul_inv = -1
    for i in range(26):
        inverse = det * i
        if inverse % 26 == 1:
            mul_inv = i
            break
    return mul_inv

if __name__ == "__main__":

    # to accept key from the user at the time of invoking the application
    parser = argparse.ArgumentParser(description='Hill Cipher encryption-decryption')
    parser.add_argument('--key', default='temp', type=str, help='Key, should have a length that is a perfect square.')
    args = parser.parse_args()
    key = (args.key).lower()

    #check key
    check_key(key)
    key_len = len(key)

    #lenght of each cipher block
    n = int(math.sqrt(key_len))

    message = input('Enter the message: ')

    #removing spaces
    message = message.replace(" ", "")
    mes_len = len(message)

    #padding, if required
    message_padded = pad_message(message, n)

    #converting string to lower case
    mes = message_padded.lower()

    #converting key to matrix
    k = np.array(convert_to_num(key))
    k = np.reshape(k, (-1, n))

    #converting message to blocks of numbers
    m = convert_msg(mes, n)

    #encrypting
    encrypted_msg = encrypt(k, m)
    print("Encrypted message: ", encrypted_msg)

    #decrypting
    msg_received = encrypted_msg
    mr = convert_msg(msg_received, n)
    decrypted_msg = decrypt(k, mr)
    print("Decrypted message: ", decrypted_msg)
