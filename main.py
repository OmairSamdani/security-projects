import hashlib
import os
from colorama import Fore, Style


def load_malicious_hashes(file_path):
    """
    Returns a collection of hash strings loaded from a file
    and is stored as a set.

    Example:
        load_malicious_hashes("malicious_hashes.txt") ->
            {'189581b786f59f29c4356888e7a3b8e4',
            '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
            'd383caabf6289b8ad52e401dafb20fb301ec3b760d1708e2501e5a39f130a1fc'}
    """
    with open(file_path, "r") as f:
        return set(line.strip() for line in f)


def sha256_hash_calculator(file):
    """
    Returns the SHA-256 hash for a file by reading it in binary mode.

    Example:
        sha256_hash_calculator(file1.txt) -> 89b3202d4ddf3f09b96854b17b9164322bd30ad63f26db0239e0b632e262fc04
    """
    # Open file in binary mode
    with open(file_path, "rb") as f:
        sha256content = f.read()

    # Generate SHA-256 hash
    sha256_hash = hashlib.sha256()
    sha256_hash.update(sha256content)
    print("SHA-256:", sha256_hash.hexdigest())

    # Return hashes as hex strings
    return sha256_hash.hexdigest()


def md5_hash_calculator(file):
    """
    Returns the MD5 hash for a file by reading it in binary mode.

    Example:
        md5_hash_calculator(file1.txt) -> a6cef77b894de673d3e8c8bc1977331b
    """
    # Open file in binary mode
    with open(file_path, "rb") as f:
        md5content = f.read()

    # Generate MD5 hash
    md5_hash = hashlib.md5()
    md5_hash.update(md5content)
    print("MD5:", md5_hash.hexdigest())

    # Return hashes as hex strings
    return md5_hash.hexdigest()


# We load in the malicious hashes text file we created to check against the files we have
malicious_hashes = load_malicious_hashes("malicious_hashes.txt")
print("Welcome to Omair's Malicious Hash Checker. Enter a valid file path or press ENTER to check all files.")

# Main loop
while True:
    folder_path = "test_files"

    # While loop asking for user input for a file path to check against the malicious hashes
    while True:
        file_or_folder = input("Enter file: ")  # Enter a file path or press enter to check all files

        # If user presses Enter then we exit the loop
        if file_or_folder == "":
            file_to_scan = [os.path.join(folder_path, f) for f in os.listdir(folder_path)]
            break

        # If a user gives a file path
        elif os.path.isfile(file_or_folder):
            file_to_scan = [file_or_folder]
            break

        # If it's a folder path
        elif os.path.isdir(file_or_folder):
            file_to_scan = [os.path.join(file_or_folder, f) for f in os.listdir(file_or_folder)]
            break

        else:
            print("Invalid path. Please try again.\n")

    # For loop to scan all the files
    for file_path in file_to_scan:
        filename = os.path.basename(file_path)
        print(Fore.BLUE + "\nScanning file:", filename + Style.RESET_ALL)

        # Try to open the file in binary mode
        try:
            with open(file_path, "rb") as f:
                content = f.read()

        # If it cannot be opened in binary mode then it outputs "Could not read {filename}"
        except Exception as e:
            print(f"Could not read {filename}: {e}")
            continue

        md5_digest = md5_hash_calculator(file_path)  # MD5 hash
        sha256_digest = sha256_hash_calculator(file_path) # SHA256 hash

        if md5_digest in malicious_hashes or sha256_digest in malicious_hashes:
            print(Fore.RED + "[ALERT] Malicious file detected!" + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "File is clean" + Style.RESET_ALL)

    # Asking user input again
    again = input("\nScan again (y/n): ").lower()
    if (again != "y") and (again != "yes"):
        print("Existing scanner.")
        break
