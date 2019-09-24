from __future__ import print_function, unicode_literals
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import shutil
from os import path, stat, remove, listdir
import fnmatch
from cryptography.fernet import Fernet, InvalidToken, InvalidSignature
import argparse
import timeit
from PyInquirer import style_from_dict, Token, prompt, Separator
from pprint import pprint


x = """

                                                                ___                    ___     ___                 
                                                               (   )                  (   )   (   )                
   .-..    ___ .-.      .--.       .--.      .--.    ___ .-.    | |_       .--.     .-.| |     | |.-.    ___  ___  
  /    \  (   )   \    /    \    /  _  \    /    \  (   )   \  (   __)    /    \   /   \ |     | /   \  (   )(   ) 
 ' .-,  ;  | ' .-. ;  |  .-. ;  . .' `. ;  |  .-. ;  |  .-. .   | |      |  .-. ; |  .-. |     |  .-. |  | |  | |  
 | |  . |  |  / (___) |  | | |  | '   | |  |  | | |  | |  | |   | | ___  |  | | | | |  | |     | |  | |  | |  | |  
 | |  | |  | |        |  |/  |  _\_`.(___) |  |/  |  | |  | |   | |(   ) |  |/  | | |  | |     | |  | |  | '  | |  
 | |  | |  | |        |  ' _.' (   ). '.   |  ' _.'  | |  | |   | | | |  |  ' _.' | |  | |     | |  | |  '  `-' |  
 | |  ' |  | |        |  .'.-.  | |  `\ |  |  .'.-.  | |  | |   | ' | |  |  .'.-. | '  | |     | '  | |   `.__. |  
 | `-'  '  | |        '  `-' /  ; '._,' '  '  `-' /  | |  | |   ' `-' ;  '  `-' / ' `-'  /     ' `-' ;    ___ | |  
 | \__.'  (___)        `.__.'    '.___.'    `.__.'  (___)(___)   `.__.    `.__.'   `.__,'       `.__.    (   )' |  
 | |                                                                                                      ; `-' '  
(___)                                                                                                      .__.'   

"""


def creds():
    print(x)
    print("<--------------------------------->")
    print("\nElia Peretz id: 999999999")
    print("\nPOC Cyber project\n")
    print("<--------------------------------->")


def get_file_list(pattern):
    """
    This function get the current dir file of selected extension
    :param pattern:
    :return:
    """

    s = listdir('.')
    a = []
    for entry in s:
        if fnmatch.fnmatch(entry, pattern):
                a.append(entry)
    return a


def get_key(set_key):
    """
    this function is used to convert the string input from the file to the key format needed
    and then return the key format
    :param set_key:
    :return:
    """

    password_provided = set_key  # This is input in the form of a string
    password = password_provided.encode()  # Convert to type bytes
    salt = b'salt_'  # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once
    return key


def duplicate_file(file1):
    """
    this function is used to duplicate the original file that we trying to crack
    so that we wont damage the original file
    :param file1:
    :return:
    """
    # make a duplicate of an existing file
    if path.isfile(file1):
        # get the path to the file in the current directory
        src = path.realpath(file1)

        # let's make a backup copy by appending "bak" to the name

        dst = '{}.bak'.format(src)

        # now use the shell to make a copy of the file
        shutil.copy(src, dst)

        # copy over the permissions,modification
        shutil.copystat(src, dst)


def hash_file(filename):
    """
    this function used to get the hashing of the file so we can authenticate the source of the .bak file
    :param filename:
    :return:
    """
    h = hashes.Hash(hashes.SHA256(), backend=default_backend())
    # open file for reading in binary mode
    with open(filename, 'rb') as file:
        # loop till the end of the file
        chunk = 0
        while chunk != b'':
            # read only 1024 bytes at a time
            chunk = file.read(1024)
            h.update(chunk)
    # return the hex representation of digest
    return h.finalize()


# ---------------------------------------------------------
def encrypt(input_file: str, key):
    """
    this function was used to create the test.encrypted file that we trying to crack
    :param input_file:
    :param key:
    :return:
    """
    # key = b'fWn9BDrXryrtcxjXhaO2BR9Oc_bS_zk1k4b6aL_0rbI='  # the key is "password"
    output_file = '{}.encrypted'.format(input_file.split('.')[0])

    with open(input_file, 'rb') as f:
        data = f.read()

    fernet = Fernet(key)  # assign the key to the var
    encrypted = fernet.encrypt(data)  # encrypting the data from the file

    with open(output_file, 'wb') as f:
        f.write(encrypted)


# ---------------------------------------------------------


def decrypt(key_test, enc_file):
    """
    this function used to try decrypt the file with a given key
    :param key_test:
    :param enc_file:
    :return:
    """
    key = key_test  # Use one of the methods to get a key (it must be the same as used in encrypting)
    input_file = enc_file
    output_file = enc_file.split('.')[0] + '.txt'

    with open(input_file, 'rb') as f:
        data = f.read()

    fernet = Fernet(key)  # assign the key to the var
    try:
        encrypted = fernet.decrypt(data)
    except (InvalidSignature, InvalidToken):  # if we get the wrong key this exceptions are raised
        return False

    with open(output_file, 'wb') as f:  # if we got the right key we decrypt the file
        f.write(encrypted)
    return True


def start_cracking(args):
    """
    this function is the brutforce attempts on the file
    :param args:
    :return:
    """
    with open("myhasefile.txt", "rb") as f:
        file_hase = f.read()
        this_hase = hash_file(args.get('enc_file') + ".bak")
        if file_hase != this_hase:  # we make sure that the file is the one we created
            print("Something is fishy")
            quit()

    with open(args.get('pw_list'), "r") as current_pass:
        attempt = 0
        for attempts in current_pass:  # loop through the list of password trying one by one
            test_key = get_key(attempts.rstrip())  # we remove any char that is not the string like "" and line brake
            print(f"trying: {attempts.rstrip()}", end="\r", flush=True)
            # print("\r {}".format(attempts), end="")
            attempt = decrypt(test_key, args.get('enc_file'))
            if attempt:
                print(f"\nthe password is: {attempts}")
                cleanup(args)
                return
            else:
                pass
        if not attempt:
            print("No password match found")
    return


def cleanup(args):
    """
    this function is used to cleanup any temp file that we created for this attempt if we didn't found the key
    this function wont be called
    :param args:
    :return:
    """

    remove(args.get('enc_file') + ".bak")
    remove("myhasefile.txt")
    return


def start_qa():
    style = style_from_dict({
        Token.Separator: '#cc5454',
        Token.QuestionMark: '#673ab7 bold',
        Token.Selected: '#cc5454',  # default
        Token.Pointer: '#673ab7 bold',
        Token.Instruction: '',  # default
        Token.Answer: '#f44336 bold',
        Token.Question: '',
    })

    questions = [
        {
            'type': 'list',
            'message': 'What do you wanna do today',
            'name': 'action',
            'choices': ['encrypt', 'decrypt', 'Brut force']
        }
    ]

    questions2 = [
        {
            'type': 'password',
            'message': 'Choose your password',
            'name': 'password'
        },
        {
            'type': 'list',
            'name': 'file_name',
            'message': 'Choose file to encrypt',
            'choices': get_file_list("*.txt"),
            'filter': lambda val: val.lower()
        }
    ]

    questions3 = [
        {
            'type': 'list',
            'name': 'enc_file',
            'message': 'Choose file to crack',
            'choices': get_file_list("*.encrypted"),
            'filter': lambda val: val.lower()
        },
        {
            'type': 'list',
            'name': 'pw_list',
            'message': 'Choose password list',
            'choices': get_file_list("*.txt"),
            'filter': lambda val: val.lower(),

        }
    ]

    questions4 = [
        {
            'type': 'password',
            'message': 'what is your password',
            'name': 'password'
        },
        {
            'type': 'list',
            'name': 'file_name',
            'message': 'Choose file to decrypt',
            'choices': get_file_list("*.encrypted"),
            'filter': lambda val: val.lower()
        }
    ]
    answers = prompt(questions, style=style)
    if answers.get("action") == 'encrypt':
        enc = prompt(questions2, style=style)
        file_name = enc.get('file_name')
        key_file = file_name.split('.')[0]
        key = get_key(enc.get('password'))
        encrypt(file_name, key)
        with open(f'{key_file}key.txt', 'wb') as f:
            f.write(key)
        remove(enc.get('file_name'))
        print(f"The file {enc.get('file_name')} is encrypted")
        exit(1)
    elif answers.get("action") == 'Brut force':
        brt = prompt(questions3, style=style)
        return brt
    else:
        dec = prompt(questions4, style=style)
        key = get_key(dec.get('password'))
        dec_attempt = decrypt(key, dec.get('file_name'))
        if dec_attempt:
            print(f"The file {dec.get('file_name')} is unlocked")
            remove(dec.get('file_name'))
            exit(1)
        else:
            print("wrong password")
            exit(1)


def main():
    args = start_qa()
    try:
        if stat(args.get('enc_file')).st_size == 0:  # make sure that the file isn't empty and that there is a file
            return 1
    except FileNotFoundError:
        print("File not found")
        return 1
    if not path.isfile(args.get('enc_file') + ".bak"):  # checks if we already created .bak file if none makes one
        duplicate_file(args.get('enc_file'))
    if not path.isfile("myhasefile.txt"):  # checks if we already created hash value file if none makes one
        with open("myhasefile.txt", "wb") as f:
            f.write(hash_file(args.get('enc_file') + ".bak"))
    start_cracking(args)
    return 0


if __name__ == "__main__":
    start = timeit.default_timer()
creds()
res = main()
end = timeit.default_timer()
print(f'timed: {end-start}')
exit(res)


