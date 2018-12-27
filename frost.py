#############################################################################
## Frost - File Encryption/Decryption                                      ##
#############################################################################
## Description: Program to encrypt or decrypt file contents using AES      ##
##  encryption. Can be run interactively or completely from command line   ##
##  arguments.                                                             ##
#############################################################################
## Author: Rayne                                                           ##
## Email: madcityhacker@gmail.com                                          ##
## Website: madcityhacker.com                                              ##
## Version: 1.0.0                                                          ##
## License: GNU GPL v3                                                     ##
#############################################################################


# Module Imports
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from platform import system
import argparse
import getpass
import os

# Function to clear the current terminal screen
def clearScreen():
    # Check for operating system type
    if system().lower() == 'windows':
	    os.system('cls')
    else:
	    os.system('clear')

# Padding function
def pad(string):
    return string + (bs - len(string) % bs) * chr(bs - len(string) % bs)

# Remove padding function
def unpad(string):
    return string[:-ord(string[len(string)-1:])]

# Function to encrypt input 
def encrypt(cleartext, key):
    padded = pad(cleartext)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encoded = base64.b64encode(iv + cipher.encrypt(padded))
    return encoded

# Function to decrypt input
def decrypt(encrypted, key):
    decoded = base64.b64decode(encrypted)
    iv = decoded[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cleartext = unpad(cipher.decrypt(decoded[AES.block_size:])).decode('utf-8')
    return cleartext

# Main
if system().lower() != 'windows':
    import readline

# Clear the screen
clearScreen()

# Print header information
print '\n'
print '#' * 80
print ' ' * 20 + 'Frost - File Encryption/Decryption'
print '#' * 80 + '\n'

# Create command line arguments
parser = argparse.ArgumentParser()
parser.add_argument('-f', '--file', help='File to encrypt or decrypt')
parser.add_argument('-o', '--output', help='File to output encrypted or decrypted value.')
parser.add_argument('-p', '--pwd', help='Password to encrypt or decrypt input with; use quotes for passphrases')
parser.add_argument('-s', '--showpwd', help='Show password as it is being typed in interactive mode', action='store_true')
parser.add_argument('method', help='Choose \'encrypt\' or \'decrypt\' for encryption or decryption', nargs='?', default='none')
args = parser.parse_args()

#Check to see if each argument is populated, and if not, prompt for value
if args.method not in {'encrypt', 'decrypt', 'none'}:
    print 'Method not valid. Please enter encrypt or decrypt.'
    quit()

if args.method == 'none':
    option = raw_input('Please enter method [encrypt/decrypt]: ')
else:
    option = args.method

if args.file is None:
    fileName = raw_input('Enter file path: ')
else:
    fileName = args.file

if not os.path.exists(fileName):
    print 'File not found. Please enter a valid file path.'
    quit()

if args.output is None:
    outputName = raw_input('Enter output file: ')
else:
    outputName = args.output

if args.pwd is None:
    if args.showpwd:
        key = raw_input('Enter encryption passphrase: ')
    else:
        key = getpass.getpass('Enter encryption passphrase: ')
else:
    key = args.pwd
    print '[CAUTION] Entering a password as an argument is dangerous! Please ensure any\ncommand line history files are sanitized to make sure accidental leakage of the\nencryption password is prevented.\n\n'

# Read content of input file
fileR = open(fileName, 'r')
string = fileR.read()
fileR.close()

# Set up encryption key information
bs = 32
encryptedKey = hashlib.sha256(key.encode()).digest()

# Function to encrypt or decrypt, depending on input choice; writes value to output file after performing function
if option == 'encrypt':
    encryptedValue = encrypt(string, encryptedKey)
    fileW = open(outputName, 'w')
    fileW.write(encryptedValue)
    fileW.close()
    print 'Encrypted value written to \'{}\'.'.format(outputName)
elif option == 'decrypt':
    decryptedValue = decrypt(string, encryptedKey)
    fileW = open(outputName, 'w')
    fileW.write(decryptedValue)
    fileW.close()
    print 'Decrypted value written to \'{}\'.'.format(outputName)
