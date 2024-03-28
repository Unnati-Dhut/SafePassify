import getpass
import json
import os
import random
import string
import pyperclip
import re
from cryptography.fernet import Fernet

# Function to generate a key for encryption/decryption
def generate_key():
    return Fernet.generate_key()

# Function to load the encryption key from file or generate a new one if it doesn't exist
def load_or_generate_key():
    key_file = "key.key"
    if os.path.exists(key_file):
        with open(key_file, 'rb') as file:
            return file.read()
    else:
        key = generate_key()
        with open(key_file, 'wb') as file:
            file.write(key)
        return key

# Function to generate a random password of a specified length
def generate_password(length):
    # Define character sets for each type of character
    uppercase_chars = string.ascii_uppercase
    lowercase_chars = string.ascii_lowercase
    digit_chars = string.digits
    special_chars = string.punctuation

    # Ensure each character type is included at least once
    password = random.choice(uppercase_chars)
    password += random.choice(lowercase_chars)
    password += random.choice(digit_chars)
    password += random.choice(special_chars)

    # Generate the remaining characters
    remaining_length = length - 4  # 4 characters already chosen
    password += ''.join(random.choices(uppercase_chars + lowercase_chars + digit_chars + special_chars, k=remaining_length))

    # Shuffle the password to ensure randomness
    password_list = list(password)
    random.shuffle(password_list)
    password = ''.join(password_list)

    return password


# Function to encrypt data
def encrypt_data(data, key):
    cipher_suite = Fernet(key)
    encrypted_data = {}
    for app_name, entry in data.items():
        encrypted_entry = {}
        for key, value in entry.items():
            encrypted_entry[key] = cipher_suite.encrypt(value.encode()).decode()
        encrypted_data[app_name] = encrypted_entry
    return encrypted_data

# Function to decrypt data
def decrypt_data(encrypted_data, key):
    cipher_suite = Fernet(key)
    decrypted_data = {}
    for app_name, encrypted_entry in encrypted_data.items():
        decrypted_entry = {}
        for key, value in encrypted_entry.items():
            decrypted_entry[key] = cipher_suite.decrypt(value.encode()).decode()
        decrypted_data[app_name] = decrypted_entry
    return decrypted_data

# Function to load data from file
def load_data(file_name, key):
    if os.path.exists(file_name):
        with open(file_name, 'r') as file:
            encrypted_data = json.load(file)
            return decrypt_data(encrypted_data, key)
    else:
        return {}

# Function to save data to file
def save_data(data, file_name, key):
    encrypted_data = encrypt_data(data, key)
    with open(file_name, 'w') as file:
        json.dump(encrypted_data, file, indent=4)

# Function to check password strength
def check_password_strength(password):
    length = len(password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_special = re.search(r'[!@#$%^&*()_+{}\[\]:;.,<>\|\\\/?]', password)
    
    if length >= 8 and has_upper and has_lower and has_digit and has_special:
        return "Strong"
    elif length >= 8 and (has_upper or has_lower or has_digit):
        return "Moderate"
    else:
        return "Weak"

# Function to add a new entry to the password manager
def add_entry(data):
    username = input("Enter username: ")
    app_name = input("Enter app name/website: ")
    
    password_choice = input("Do you want to generate a password? (y/n): ").strip().lower()
    if password_choice == 'y':
        length = int(input("Enter the length of the password: "))
        password = generate_password(length)
    else:
        password = getpass.getpass("Enter password: ")  # Masking password input

    strength = check_password_strength(password)
    print("Password strength:", strength)

    entry = {
        "username": username,
        "password": password,
        "app_name": app_name
    }

    data[app_name] = entry
    save_data(data, "passwords.json", key)
    print("Entry added successfully!")
    copy_password(password)

# Function to display all entries in the password manager
def display_entries(data):
    for app_name, entry in data.items():
        print(f"App/Website Name: {app_name}")
        print(f"Username: {entry['username']}")
        print(f"Password: {entry['password']}")
        print()

# Function to copy password to clipboard
def copy_password(password):
    pyperclip.copy(password)
    print("Password copied to clipboard!!!")

# Main function
def main():
    global key
    key = load_or_generate_key()
    data = load_data("passwords.json", key)

    while True:
        print("\nPassword Manager Menu:")
        print("1. Add New Entry")
        print("2. Display All Entries")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            add_entry(data)
        elif choice == '2':
            display_entries(data)
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 3.")

if __name__ == "__main__":
    main()
