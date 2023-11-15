#REFERENCES:
#Cryptography library - https://pypi.org/project/cryptography/
#https://github.com/abhishake21/Encryption-App
#https://stackoverflow.com/questions/22058048/hashing-a-file-in-python

# Importing cryptography library
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Importing required libraries
import os
import base64
import stdiomask
import hashlib
import sys
from tqdm import tqdm


#credentials start

username = 'master'

uname = input('\nEnter username\n')

passwd = input('\nEnter password\n')

md5 = hashlib.md5(passwd.encode('utf8')).hexdigest()
#print(md5.hexdigest().encode('utf8'))

hpasswd = '1405d1abfe132a99db48a8d42b1b10a9'

#credentials end

#main functionality start
def menu():
    choice = input('\n1. Encrypt a file\n2. Decrypt a file\n\nType "quit" to exit.\n\n')

    if choice == '1':
        print('\tTo Encrypt a file enter Password, Salt and file-location. Type "menu" to select different option or "quit" to exit.')
        encfile()
    elif choice == '2':
        print('\tTo Decrypt a file enter Password, Salt and file-location. Type "menu" to select different option or "quit" to exit.')
        decfile()
    elif choice == 'quit':
        print('\nProgram Ended.')
    else:
        print('\nEnter below choices only')
        menu()


# os.walk() Error Handler
def enc_walk_error_handler(exception_instance):
    print('\n\n\tSomething went wrong.')
    print('''
    > Check if file location and name are correct.
    Eg - D:/User/Secretfiles/

    Type "menu" to select different option or "quit" to exit.\n
    ''')
    encfolder()
def dec_walk_error_handler(exception_instance):
    print('\n\n\tSomething went wrong.')
    print('''
    > Wrong Password and/or Salt entered.
    > Check if folder location and name are correct.
    Eg - D:/User/Secretfiles/

    Type "menu" to select different option or "quit" to exit.\n
    ''')
    decfolder()


# File Encryption function
def encfile():

    upassword = stdiomask.getpass(prompt='\nEnter password - ', mask='*')

    if upassword == 'quit':
        print('Program Ended.')
    elif upassword == 'menu':
        menu()
    else:
        usalt = stdiomask.getpass(prompt='Enter Salt(leave blank if not required) - ', mask='*')

        if usalt == 'quit':
            print('\nProgram Ended.')
        elif usalt == 'menu':
            menu()
        else:
            def enc():
                fileln = input('Enter file locations(separated by comma) - ').split(',')
                password=bytes(upassword,'utf-8')
                salt=bytes(usalt,'utf-8')

                try:
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=100000,
                        backend=default_backend())

                    key = base64.urlsafe_b64encode(kdf.derive(password))
                    f = Fernet(key)

                    cnt = len(fileln)

                    with tqdm(total=cnt) as pbar:
                        for file in fileln:
                            with open(file,'rb') as original_file:
                                original = original_file.read()

                            encrypted = f.encrypt(original)

                            with open (file,'wb') as encrypted_file:
                                encrypted_file.write(encrypted)
                            pbar.update(1)

                    print('\nAll files are Encrypted.')

                except:
                    print('\n\tSomething went wrong.')
                    print('''
                    Check if file location and name are correct.
                    Eg - D:/User/Secretfiles/secrets.txt

                    Type "menu" to select different option or "quit" to exit.\n
                    ''')
                    encfile()
            enc()
    menu()

# File Decryption function
def decfile():

    upassword = stdiomask.getpass(prompt='\nEnter password - ', mask='*')

    if upassword == 'quit':
        print('\nProgram Ended.')
    elif upassword == 'menu':
        menu()
    else:
        usalt = stdiomask.getpass(prompt='Enter Salt(leave blank if not required) - ', mask='*')

        if usalt == 'quit':
            print('\nProgram Ended.')
        elif usalt == 'menu':
            menu()
        else:
            def dec():
                fileln = input('Enter file locations(separated by comma) - ').split(',')
                password=bytes(upassword,'utf-8')
                salt=bytes(usalt,'utf-8')

                try:
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=100000,
                        backend=default_backend())

                    key = base64.urlsafe_b64encode(kdf.derive(password))
                    f = Fernet(key)

                    cnt = len(fileln)

                    with tqdm(total=cnt) as pbar:
                        for file in fileln:
                            with open(file,'rb') as original_file:
                                original = original_file.read()

                            decrypted = f.decrypt(original)

                            with open (file,'wb') as decrypted_file:
                                decrypted_file.write(decrypted)
                            pbar.update(1)
                    print('\nAll files are Decrypted.')


                except:
                    print('\n\tSomething went wrong.')
                    print('''
                    > Wrong Password and/or Salt entered.
                    > Check if file location and name are correct.
                    Eg - D:/User/Secretfiles/secrets.txt

                    Type "menu" to select different option or "quit" to exit.\n
                    ''')
                    decfile()
            dec()

#main functionality end

#login verification

if(uname == username and hpasswd == md5):
    print('\nWelcome to the VAULT..!\nPlease be mindful of your choices.\n\n')

    menu()    

else:
    print('\nInvalid Username or Password.... Goodbye\n\n')
    