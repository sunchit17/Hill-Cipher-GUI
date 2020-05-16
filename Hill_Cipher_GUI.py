from tkinter import *
from PIL import ImageTk, Image
import numpy as np
import math

root = Tk()
root.title('Hill Cipher GUI')
root.geometry("480x400")
root.resizable(False,False)

background_image = ImageTk.PhotoImage(Image.open("crypt.jpg"))
background_label = Label(image=background_image,height=400,width=400)
background_label.place(x=0, y=0, relwidth=1, relheight=1)

credits_label = Label(text="Cryptography Assignment by Sunchit, Akshat and Saurav")
credits_label.place(relx=1.0, rely=1.0, anchor='se')

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

def convert_to_num(l):
    """
    Argument: String
    Returns a list of corresponding numbers. Eg, abz -> [0, 1, 25]
    """
    return [(ord(c)-97) for c in l]

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


def show_encrypt():
    key = 'temp'
    key_len = len(key)
    n = int(math.sqrt(key_len))
    # convert key to matrix
    k = np.array(convert_to_num(key))
    k = np.reshape(k, (-1, n))

    message = text_entry.get()
    text_entry.delete(0,END)
    decrypt_entry.delete(0,END)
    message = message.replace(" ","")
    mes_len = len(message)
    message_padded = pad_message(message,n)
    mes = message_padded.lower()
    m = convert_msg(mes, n)

    encrypted_msg = encrypt(k, m)
    decrypt_entry.insert(0,encrypted_msg)

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


def show_decrypt():
    key = 'temp'
    key_len = len(key)
    n = int(math.sqrt(key_len))
    # convert key to matrix
    k = np.array(convert_to_num(key))
    k = np.reshape(k, (-1, n))

    msg_received = decrypt_entry.get()
    text_entry.delete(0,END)
    decrypt_entry.delete(0,END)
    mr = convert_msg(msg_received, n)
    decrypted_msg = decrypt(k, mr)

    text_entry.insert(0,decrypted_msg)

text_entry = Entry(root,width=50,font=("Helvetica",10))
text_entry.grid(row=0,column=1,padx=20,pady=(10,0))

text_entry_label = Label(root,text="Enter Text: ")
text_entry_label.grid(row=0,column=0,padx=5,pady=(10,0))

encrypt_btn = Button(root,text="Encrypt Text",bg="black",fg="white",command=show_encrypt)
encrypt_btn.grid(row=1,column=1,pady=(8,0))


decrypt_entry = Entry(root,width=50,font=("Helvetica",10))
decrypt_entry.grid(row=5,column=1,padx=20,pady=(10,0))

decrypt_entry_label = Label(root,text="Encrypted Text: ")
decrypt_entry_label.grid(row=5,column=0,padx=5,pady=(10,0))

decrypt_btn = Button(root,text="Decrypt Text",bg="black",fg="white",command=show_decrypt)
decrypt_btn.grid(row=6,column=1,pady=(8,0))



root.mainloop()
