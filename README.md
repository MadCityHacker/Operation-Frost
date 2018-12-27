# Operation-Frost

Frost is a simply Python script that allows for encrypting and decrypting the contents of a file using AES encryption. The process can be automated, through the use of command line arguments, or can be performed interactively. For additional information on how to use this program or any others created, please visit https://madcityhacker.com.

# Setup
Frost was written using Python 2.7. It has been tested on both Windows and Linux operating systems.

Installation
------------
Simply clone the repository and run `pip install -r requirements.txt`

# Usage
As mentioned previously, this program can be run interactively or via command line arguments.

Interactive Mode
----------------
To run in interactive mode, simply run `python frost.py`. You will be prompted for all required fields from there. If you want to be shown the encryption key password as you type it, simply pass in the `-s` or `--showpwd` option when running the script.

Automated Mode
--------------
There are a number of options that can be passed to the script.

 * -f or --file <FILE> - This option specifies the file contents you want to encrypt or decrypt
 * -o or --output <FILE> - This option specifies the file to write the encrypted or decrypted text to
 * -p or --pwd <PASSWORD> - This option specifies the encryption key to use for the encryption or decryption process
 
If one or more of these options are missing, they will be prompted for as they would if you were running the script in interactive mode.

Examples
--------
**Encryption**

`python frost.py -f supersecret.txt -o encrypted.txt -p ThisIsAPassword encrypt`
  * The above will encrypt the contents of `supersecret.txt` with an encryption key of `ThisIsAPassword` and write the encrypted value to `encrypted.txt`
  
**Decryption**

`python frost.py -f encrypted.txt -o secretsrevealed.txt -p ThisIsAPassword decrypt`
 * The above will decrypt the contents of `encrypted.txt` using an encryption key of `ThisIsAPassword` and write the decrypted value to `secretsrevealed.txt`
 
 Licensing
 ---------
 This program is licensed under GNU GPL v3. For more information, please reference the LICENSE file that came with this program or visit https://www.gnu.org/licenses/. 
 
 Contact Us
 ----------
 Whether you want to report a bug, send a patch, or give some suggestions on this program, please open an issue on the GitHub page or send an email to madcityhacker@gmail.com.
