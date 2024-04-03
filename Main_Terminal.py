from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_file(input_file, output_file, key):
    cipher = AES.new(key, AES.MODE_EAX)
    with open(input_file, 'rb') as f_in:
        data = f_in.read()
        ciphertext, tag = cipher.encrypt_and_digest(data)
    with open(output_file, 'wb') as f_out:
        f_out.write(cipher.nonce)
        f_out.write(tag)
        f_out.write(ciphertext)

def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f_in:
        nonce = f_in.read(16)
        tag = f_in.read(16)
        ciphertext = f_in.read()
    cipher = AES.new(key, AES.MODE_EAX, nonce) 
    data = cipher.decrypt_and_verify(ciphertext, tag)
    with open(output_file, 'wb') as f_out:
        f_out.write(data)

def main():
    choice = input("\n------------------------------------------------------\nDo you want to encrypt (E) or decrypt (D) a file? ").upper()

    if choice == 'E':
        input_file = input("Enter the path of the file to encrypt: ")
        encrypted_file = input("Enter the path of the file to save: ")
        if encrypted_file == 'self':
            encrypted_file = input_file
        auto = input('Do you have a key Y/N? ').upper()
        get_auto = True
        while get_auto == True:
            if auto == 'Y' or auto == 'YES':
                key_hex = input("Enter the key: ")
                key = bytes.fromhex(key_hex)
                get_auto = False
            elif auto == 'N' or auto == 'NO':
                key = get_random_bytes(16)
                print('\n------------------------------------------------------\nYour key is: ', key.hex(),'\n------------------------------------------------------\n')  
                get_auto = False
            else:
                print("Invalid option, select 'Y' to use your key and 'N' to generate a new one")
                get_auto = True
            
        encrypt_file(input_file, encrypted_file, key)
        print("File encrypted successfully. \n------------------------------------------------------\n")

    elif choice == 'D': 
        encrypted_file = input("Enter the path of the file to decrypt: ")
        decrypted_file = input("Enter the path of the file to save: ")
        if decrypted_file == 'self':
            decrypted_file = encrypted_file
        key_hex = input("Enter the key: ")
        key = bytes.fromhex(key_hex)
        decrypt_file(encrypted_file, decrypted_file, key)
        print("\n------------------------------------------------------\nFile decrypted successfully.\n------------------------------------------------------\n")
    else:
        print("Invalid choice. Please choose 'E' for encryption or 'D' for decryption.")
        
if __name__ == "__main__":
    loop = True
    while loop == True:
        main()
        again = input('Do you want to continue Y/N? ').upper()
        if again == 'Y' or again == 'YES':
            loop = True
        elif again == 'N' or again == 'NO':
            loop = False
        else:
            print("Invalid choice. Please choose 'N' to end the program or 'Y' to continue.")  