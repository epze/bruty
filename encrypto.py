import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import shutil
from os import path, stat, remove
from cryptography.fernet import Fernet, InvalidToken, InvalidSignature
import argparse
import timeit



x= """

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


# this function is used to convert the string input from the file to the key format needed
# and then return the key format
def get_key(set_key):
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


# this function is used to duplicate the original file that we trying to crack
# so that we wont damage the original file
def duplicate_file(file1):
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


# this function used to get the hashing of the file so we can authenticate the source of the .bak file
def hash_file(filename):
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


# this function was used to create the test.encrypted file that we trying to crack
# ---------------------------------------------------------
def encrypt(input_file: str) -> None:
    key = b'fWn9BDrXryrtcxjXhaO2BR9Oc_bS_zk1k4b6aL_0rbI='  # the key is "password"
    output_file = 'test.encrypted'

    with open(input_file, 'rb') as f:
        data = f.read()

    fernet = Fernet(key)  # assign the key to the var
    encrypted = fernet.encrypt(data)  # encrypting the data from the file

    with open(output_file, 'wb') as f:
        f.write(encrypted)


# ---------------------------------------------------------


# this function used to try decrypt the file with a given key
def decrypt(key_test, enc_file):
    key = key_test  # Use one of the methods to get a key (it must be the same as used in encrypting)
    input_file = enc_file
    output_file = 'test.txt'

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


# this function is the brutforce attempts on the file
def start_cracking(args):
    with open("myhasefile.txt", "rb") as f:
        file_hase = f.read()
        this_hase = hash_file(args.enc_file + ".bak")
        if file_hase != this_hase:  # we make sure that the file is the one we created
            print("Something is fishy")
            quit()

    with open(args.pwlist, "r") as current_pass:
        attempt = 0
        for attempts in current_pass:  # loop through the list of password trying one by one
            test_key = get_key(attempts.rstrip())  # we remove any char that is not the string like "" and line brake
            print(f"trying: {attempts.rstrip()}", end="\r", flush=True)
            # print("\r {}".format(attempts), end="")
            attempt = decrypt(test_key, args.enc_file)
            if attempt:
                print(f"\nthe password is: {attempts}")
                cleanup(args)
                return
            else:
                pass
        if not attempt:
            print("No password match found")
    return


# this function is used to cleanup any temp file that we created for this attempt if we didn't found the key
# this function wont be called
def cleanup(args):
    remove(args.enc_file + ".bak")
    remove("myhasefile.txt")
    return


def args_initializer(parser=None, param=None):
    if parser is None:
        parser = argparse.ArgumentParser(description="This script takes ")
    if param is None:
        parser.add_argument("--enc_file", required=True, help="here you give the encrypted file")
        parser.add_argument("--pwlist", required=True, help="the path to the combo list")
        return parser.parse_args()


def main():
    args = args_initializer()
    try:
        if stat(args.enc_file).st_size == 0:  # make sure that the file isn't empty and that there is a file
            return 1
    except FileNotFoundError:
        print("File not found")
        return 1
    if not path.isfile(args.enc_file + ".bak"):  # checks if we already created .bak file if none makes one
        duplicate_file(args.enc_file)
    if not path.isfile("myhasefile.txt"):  # checks if we already created hash value file if none makes one
        with open("myhasefile.txt", "wb") as f:
            f.write(hash_file(args.enc_file + ".bak"))
    start_cracking(args)
    return 0


if __name__ == "__main__":
    start = timeit.default_timer()
creds()
res = main()
end = timeit.default_timer()
print(f'timed: {end-start}')
exit(res)

