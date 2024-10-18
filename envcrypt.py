#!/usr/bin/env python3
import os
import sys
import json
import argparse
import base64
import hashlib
import logging
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, Tuple

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from threading import Lock

# Initialize logger with rotation
from logging.handlers import RotatingFileHandler

logger = logging.getLogger("EnvCryptor")
logger.setLevel(logging.DEBUG)

# Create handlers
c_handler = logging.StreamHandler()
f_handler = RotatingFileHandler("envcrypt.log", maxBytes=5 * 1024 * 1024, backupCount=5)
c_handler.setLevel(logging.INFO)
f_handler.setLevel(logging.DEBUG)

# Create formatters and add to handlers
c_format = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
f_format = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
c_handler.setFormatter(c_format)
f_handler.setFormatter(f_format)

# Add handlers to the logger
logger.addHandler(c_handler)
logger.addHandler(f_handler)


class KeyManager:
    """Class for managing encryption keys securely."""

    def __init__(self, key_directory: str = "keys"):
        """
        Initialize the KeyManager.

        Args:
            key_directory (str): Directory where keys will be stored.
        """
        self.key_directory = key_directory
        self.lock = Lock()
        self._ensure_key_directory()

    def _ensure_key_directory(self):
        """Ensure that the key directory exists with proper permissions."""
        if not os.path.exists(self.key_directory):
            os.makedirs(self.key_directory, mode=0o700, exist_ok=True)
            logger.debug(
                f"Created key directory at {self.key_directory} with permissions 700."
            )
        else:
            logger.debug(f"Key directory {self.key_directory} already exists.")

    def generate_key(self, key_name: str, key_length: int = 32) -> str:
        """
        Generate a new secure key.

        Args:
            key_name (str): Name of the key.
            key_length (int): Length of the key in bytes.

        Returns:
            str: Path to the generated key file.
        """
        with self.lock:
            key_path = os.path.join(self.key_directory, f"{key_name}.key")
            if os.path.exists(key_path):
                logger.error(f"Key '{key_name}' already exists at {key_path}.")
                raise FileExistsError(f"Key '{key_name}' already exists.")

            # Generate a secure random key
            key = get_random_bytes(key_length)
            logger.debug(
                f"Generated a new key '{key_name}' with length {key_length} bytes."
            )

            # Optionally, encrypt the key before storing it
            # For simplicity, we're storing it as is. In production, consider encrypting keys.

            try:
                with open(key_path, "wb") as f:
                    f.write(key)
                os.chmod(key_path, 0o600)  # Set strict permissions
                logger.info(f"Key '{key_name}' generated and stored at {key_path}.")
            except IOError as e:
                logger.error(f"Failed to write key '{key_name}' to file: {e}")
                raise

            return key_path

    def load_key(self, key_name: str) -> bytes:
        """
        Load a key from the key directory.

        Args:
            key_name (str): Name of the key to load.

        Returns:
            bytes: The key bytes.
        """
        with self.lock:
            key_path = os.path.join(self.key_directory, f"{key_name}.key")
            if not os.path.exists(key_path):
                logger.error(f"Key '{key_name}' does not exist at {key_path}.")
                raise FileNotFoundError(f"Key '{key_name}' does not exist.")

            try:
                with open(key_path, "rb") as f:
                    key = f.read()
                logger.debug(f"Key '{key_name}' loaded successfully from {key_path}.")
            except IOError as e:
                logger.error(f"Failed to read key '{key_name}' from file: {e}")
                raise

            return key

    def rotate_key(
        self, old_key_name: str, new_key_name: str, key_length: int = 32
    ) -> Tuple[str, str]:
        """
        Rotate an existing key by generating a new key and optionally deprecating the old key.

        Args:
            old_key_name (str): Name of the existing key to rotate.
            new_key_name (str): Name of the new key.
            key_length (int): Length of the new key in bytes.

        Returns:
            Tuple[str, str]: Paths to the old and new key files.
        """
        with self.lock:
            old_key_path = os.path.join(self.key_directory, f"{old_key_name}.key")
            new_key_path = os.path.join(self.key_directory, f"{new_key_name}.key")

            if not os.path.exists(old_key_path):
                logger.error(f"Old key '{old_key_name}' does not exist.")
                raise FileNotFoundError(f"Old key '{old_key_name}' does not exist.")

            if os.path.exists(new_key_path):
                logger.error(f"New key '{new_key_name}' already exists.")
                raise FileExistsError(f"New key '{new_key_name}' already exists.")

            # Generate new key
            new_key = get_random_bytes(key_length)
            try:
                with open(new_key_path, "wb") as f:
                    f.write(new_key)
                os.chmod(new_key_path, 0o600)
                logger.info(
                    f"New key '{new_key_name}' generated and stored at {new_key_path}."
                )
            except IOError as e:
                logger.error(f"Failed to write new key '{new_key_name}' to file: {e}")
                raise

            # Optionally, mark the old key as deprecated or archive it
            # For simplicity, we're not handling deprecation here

            logger.info(f"Key rotation: '{old_key_name}' rotated to '{new_key_name}'.")
            return old_key_path, new_key_path

    def list_keys(self) -> Dict[str, str]:
        """
        List all available keys in the key directory.

        Returns:
            Dict[str, str]: A dictionary mapping key names to their file paths.
        """
        with self.lock:
            keys = {}
            for filename in os.listdir(self.key_directory):
                if filename.endswith(".key"):
                    key_name = filename[:-4]  # Remove '.key' extension
                    key_path = os.path.join(self.key_directory, filename)
                    keys[key_name] = key_path
            logger.debug(f"Available keys: {keys}")
            return keys

    def delete_key(self, key_name: str) -> None:
        """
        Delete a key from the key directory.

        Args:
            key_name (str): Name of the key to delete.
        """
        with self.lock:
            key_path = os.path.join(self.key_directory, f"{key_name}.key")
            if not os.path.exists(key_path):
                logger.error(f"Key '{key_name}' does not exist.")
                raise FileNotFoundError(f"Key '{key_name}' does not exist.")

            try:
                os.remove(key_path)
                logger.info(f"Key '{key_name}' deleted successfully from {key_path}.")
            except OSError as e:
                logger.error(f"Failed to delete key '{key_name}': {e}")
                raise


class EnvCryptor:
    """Base class for encrypting and decrypting environment variables and secrets."""

    # Constants for encryption
    HASH_NAME = "SHA512"
    IV_LENGTH = 12
    ITERATION_COUNT = 100_000  # Increased for better security
    KEY_LENGTH = 32
    SALT_LENGTH = 16
    TAG_LENGTH = 16

    CURRENT_VERSION = "1.0"

    def __init__(self, source_file: str, key: bytes) -> None:
        """
        Initialize the EnvCryptor instance.

        Args:
            source_file (str): The path to the source file containing environment variables.
            key (bytes): The key used for encryption and decryption.
        """
        if not isinstance(key, bytes) or len(key) < 16:
            raise ValueError("Key must be bytes with a minimum length of 16 bytes.")

        self.source_file = source_file
        self.key = key
        self.lock = Lock()
        self._attributes = self.get_attributes()

    def get_attributes(self) -> Dict[str, Any]:
        """
        Get the attributes for encryption configurations.

        Returns:
            Dict[str, Any]: Encryption attributes.
        """
        return {
            "HASH_NAME": self.HASH_NAME,
            "IV_LENGTH": self.IV_LENGTH,
            "ITERATION_COUNT": self.ITERATION_COUNT,
            "KEY_LENGTH": self.KEY_LENGTH,
            "SALT_LENGTH": self.SALT_LENGTH,
            "TAG_LENGTH": self.TAG_LENGTH,
            "VERSION": self.CURRENT_VERSION,
        }

    @staticmethod
    def secure_delete(variable: Any):
        """Overwrite sensitive data in memory."""
        # Placeholder for secure deletion. Python's garbage collector handles memory management.
        pass


class EncryptionPipeline(EnvCryptor):
    """Class for managing the encryption pipeline."""

    def __init__(self, source_file: str, key: bytes) -> None:
        """
        Initialize the EncryptionPipeline instance.

        Args:
            source_file (str): Path to the source file with environment variables.
            key (bytes): The key used for encryption and decryption.
        """
        super().__init__(source_file, key)

    def encrypt(self, data: str) -> bytes:
        """
        Encrypt the data using AES GCM mode.

        Args:
            data (str): The data to be encrypted.

        Returns:
            bytes: The encrypted data including metadata, salt, IV, tag, and ciphertext.
        """
        if not isinstance(data, str):
            raise ValueError("Data to encrypt must be a string.")

        logger.debug("Starting encryption process...")

        # Generate salt and derive key
        salt = get_random_bytes(self._attributes["SALT_LENGTH"])
        logger.debug(f"Generated salt: {base64.b64encode(salt).decode()}")

        hashed_key = hashlib.pbkdf2_hmac(
            self._attributes["HASH_NAME"],
            self.key,
            salt,
            self._attributes["ITERATION_COUNT"],
            self._attributes["KEY_LENGTH"],
        )
        logger.debug("Derived encryption key from the provided key and salt.")

        # Generate IV
        iv = get_random_bytes(self._attributes["IV_LENGTH"])
        logger.debug(f"Generated IV: {base64.b64encode(iv).decode()}")

        # Initialize cipher
        cipher = AES.new(hashed_key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        logger.debug("Data encrypted and authentication tag generated.")

        # Prepare metadata
        metadata = {
            "version": self._attributes["VERSION"],
            "salt": base64.b64encode(salt).decode(),
            "iv": base64.b64encode(iv).decode(),
            "tag": base64.b64encode(tag).decode(),
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }

        # Construct the final payload
        encrypted_payload = {
            "metadata": metadata,
            "ciphertext": base64.b64encode(ciphertext).decode(),
        }

        logger.debug("Encryption payload constructed with metadata.")

        # Serialize to JSON
        encrypted_data = json.dumps(encrypted_payload).encode()

        logger.info("Encryption completed successfully.")
        return encrypted_data

    def store_encrypted(self, encrypted_data: bytes) -> None:
        """
        Store the encrypted data to a file.

        Args:
            encrypted_data (bytes): The encrypted data to store.
        """
        enc_file = self.source_file + ".enc"
        logger.debug(f"Storing encrypted data in {enc_file}...")

        try:
            with open(enc_file, "wb") as f:
                f.write(encrypted_data)
            logger.info(f"Encrypted data stored successfully in {enc_file}")
        except IOError as e:
            logger.error(f"Failed to write encrypted data to file: {e}")
            raise

    @contextmanager
    def encryption_lock(self):
        """
        Context manager for lock acquisition and release.
        """
        logger.debug("Acquiring lock for encryption...")
        with self.lock:
            yield
        logger.debug("Lock released after encryption.")

    def execute_pipeline(self, data: str) -> None:
        """
        Execute the encryption pipeline for the provided data.

        Args:
            data (str): The data to be encrypted.
        """
        logger.info("Starting encryption pipeline...")
        with self.encryption_lock():
            encrypted_data = self.encrypt(data)
            self.store_encrypted(encrypted_data)
        logger.info("Encryption pipeline executed successfully.")


class DecryptionPipeline(EnvCryptor):
    """Class for managing the decryption pipeline."""

    def __init__(self, source_file: str, key: bytes) -> None:
        """
        Initialize the DecryptionPipeline instance.

        Args:
            source_file (str): Path to the source file with encrypted data.
            key (bytes): The key used for encryption and decryption.
        """
        super().__init__(source_file, key)

    def decrypt(self, encrypted_data: bytes) -> str:
        """
        Decrypt the data using AES GCM mode.

        Args:
            encrypted_data (bytes): The encrypted data to be decrypted.

        Returns:
            str: The decrypted data.
        """
        if not isinstance(encrypted_data, bytes):
            raise ValueError("Encrypted data must be bytes.")

        logger.debug("Starting decryption process...")

        # Deserialize JSON
        try:
            payload = json.loads(encrypted_data.decode())
            logger.debug("Encrypted payload deserialized from JSON.")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode encrypted data: {e}")
            raise ValueError("Invalid encrypted data format.")

        metadata = payload.get("metadata", {})
        ciphertext_b64 = payload.get("ciphertext", "")

        # Extract metadata
        version = metadata.get("version")
        salt_b64 = metadata.get("salt")
        iv_b64 = metadata.get("iv")
        tag_b64 = metadata.get("tag")
        timestamp = metadata.get("timestamp")

        logger.debug(f"Metadata extracted: version={version}, timestamp={timestamp}")

        if not all([version, salt_b64, iv_b64, tag_b64, ciphertext_b64]):
            logger.error("Missing metadata in encrypted data.")
            raise ValueError("Incomplete metadata in encrypted data.")

        # Version handling (for future use)
        if version != self.CURRENT_VERSION:
            logger.warning(
                f"Encrypted data version {version} differs from current version {self.CURRENT_VERSION}. Proceeding with decryption."
            )

        # Decode base64 fields
        try:
            salt = base64.b64decode(salt_b64)
            iv = base64.b64decode(iv_b64)
            tag = base64.b64decode(tag_b64)
            ciphertext = base64.b64decode(ciphertext_b64)
            logger.debug("Base64-encoded fields decoded successfully.")
        except base64.binascii.Error as e:
            logger.error(f"Base64 decoding failed: {e}")
            raise ValueError("Invalid base64 encoding in encrypted data.")

        # Derive key
        hashed_key = hashlib.pbkdf2_hmac(
            self._attributes["HASH_NAME"],
            self.key,
            salt,
            self._attributes["ITERATION_COUNT"],
            self._attributes["KEY_LENGTH"],
        )
        logger.debug("Derived decryption key from the provided key and salt.")

        # Initialize cipher
        cipher = AES.new(hashed_key, AES.MODE_GCM, nonce=iv)
        logger.debug("AES GCM cipher initialized for decryption.")

        # Decrypt and verify
        try:
            decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
            logger.debug("Ciphertext decrypted and tag verified successfully.")
        except ValueError as e:
            logger.error(f"Decryption failed: {e}")
            raise ValueError(
                "Decryption failed. The data may be corrupted or the key may be incorrect."
            )

        # Convert bytes to string
        decrypted_text = decrypted_data.decode()
        logger.info("Decryption completed successfully.")
        return decrypted_text

    def store_decrypted(self, decrypted_data: str) -> None:
        """
        Store the decrypted data to a file.

        Args:
            decrypted_data (str): The decrypted data to store.
        """
        dec_file = self.source_file + ".dec"
        logger.debug(f"Storing decrypted data in {dec_file}...")

        try:
            with open(dec_file, "w") as f:
                f.write(decrypted_data)
            logger.info(f"Decrypted data stored successfully in {dec_file}")
        except IOError as e:
            logger.error(f"Failed to write decrypted data to file: {e}")
            raise

    @contextmanager
    def decryption_lock(self):
        """
        Context manager for lock acquisition and release.
        """
        logger.debug("Acquiring lock for decryption...")
        with self.lock:
            yield
        logger.debug("Lock released after decryption.")

    def execute_pipeline(self) -> None:
        """
        Execute the decryption pipeline for the provided encrypted data.
        """
        logger.info("Starting decryption pipeline...")
        with self.decryption_lock():
            enc_file = self.source_file + ".enc"
            logger.debug(f"Reading encrypted data from {enc_file}...")

            if not os.path.exists(enc_file):
                logger.error(f"Encrypted file {enc_file} does not exist.")
                raise FileNotFoundError(f"Encrypted file {enc_file} does not exist.")

            try:
                with open(enc_file, "rb") as f:
                    encrypted_data = f.read()
                logger.debug("Encrypted data read successfully.")
            except IOError as e:
                logger.error(f"Failed to read encrypted file: {e}")
                raise

            decrypted_data = self.decrypt(encrypted_data)
            self.store_decrypted(decrypted_data)
        logger.info("Decryption pipeline executed successfully.")

    def decrypt_from_file(self) -> str:
        """
        Decrypt the encrypted data from the source file and return the decrypted data.

        Returns:
            str: The decrypted data.
        """
        logger.debug(f"Reading encrypted data from {self.source_file}.enc...")
        enc_file = self.source_file + ".enc"
        if not os.path.exists(enc_file):
            logger.error(f"Encrypted file {enc_file} does not exist.")
            raise FileNotFoundError(f"Encrypted file {enc_file} does not exist.")

        try:
            with open(enc_file, "rb") as f:
                encrypted_data = f.read()
            logger.debug("Encrypted data read successfully.")
        except IOError as e:
            logger.error(f"Failed to read encrypted file: {e}")
            raise

        decrypted_data = self.decrypt(encrypted_data)
        return decrypted_data

def encrypt_env(source_file: str, key: bytes) -> None:
    """
    Encrypt the environment variables from the source file.

    Args:
        source_file (str): The source file containing environment variables.
        key (bytes): The encryption key.
    """
    pipeline = EncryptionPipeline(source_file, key)

    if not os.path.exists(source_file):
        logger.error(f"Source file {source_file} does not exist.")
        sys.exit(1)

    try:
        with open(source_file, "r") as f:
            data = f.read()
        logger.debug(f"Read data from {source_file}.")
    except IOError as e:
        logger.error(f"Failed to read source file: {e}")
        sys.exit(1)

    pipeline.execute_pipeline(data)


def decrypt_env(source_file: str, key: bytes, output: str = None) -> None:
    """
    Decrypt the environment variables from the encrypted file.

    Args:
        source_file (str): The source file with encrypted data.
        key (bytes): The decryption key.
        output (str): The output file path or '-' for stdout.
    """
    pipeline = DecryptionPipeline(source_file, key)
    try:
        decrypted_data = pipeline.decrypt_from_file()
        if output == "-" or output == "/dev/stdout":
            print(decrypted_data)
        elif output:
            pipeline.store_decrypted(decrypted_data, output)
        else:
            # Default behavior: store decrypted data in .dec file
            pipeline.store_decrypted(decrypted_data)
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        sys.exit(1)


def rotate_key(
    key_manager: KeyManager, source_file: str, old_key_name: str, new_key_name: str
) -> None:
    """
    Rotate the encryption key by decrypting with the old key and re-encrypting with the new key.

    Args:
        key_manager (KeyManager): The key manager instance.
        source_file (str): The source file with encrypted data.
        old_key_name (str): Name of the old key.
        new_key_name (str): Name of the new key.
    """
    logger.info("Starting key rotation process...")

    # Load old key
    try:
        old_key = key_manager.load_key(old_key_name)
    except Exception as e:
        logger.error(f"Failed to load old key '{old_key_name}': {e}")
        sys.exit(1)

    # Decrypt with old key
    decrypt_pipeline = DecryptionPipeline(source_file, old_key)
    try:
        decrypt_pipeline.execute_pipeline()
    except Exception as e:
        logger.error(f"Failed to decrypt with old key during rotation: {e}")
        sys.exit(1)

    dec_file = source_file + ".dec"

    # Generate and load new key
    try:
        key_manager.generate_key(new_key_name)
        new_key = key_manager.load_key(new_key_name)
    except Exception as e:
        logger.error(f"Failed to generate/load new key '{new_key_name}': {e}")
        sys.exit(1)

    # Encrypt with new key
    encrypt_pipeline = EncryptionPipeline(source_file, new_key)
    try:
        with open(dec_file, "r") as f:
            data = f.read()
        logger.debug(f"Read decrypted data from {dec_file}.")
    except IOError as e:
        logger.error(f"Failed to read decrypted file during rotation: {e}")
        sys.exit(1)

    encrypt_pipeline.execute_pipeline(data)
    logger.info("Key rotation completed successfully.")

    # Optionally, remove the decrypted file
    try:
        os.remove(dec_file)
        logger.debug(f"Removed temporary decrypted file {dec_file}.")
    except OSError as e:
        logger.warning(f"Failed to remove temporary decrypted file: {e}")


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="Encrypt and decrypt environment variables and secrets."
    )
    subparsers = parser.add_subparsers(
        dest="command", required=True, help="Sub-commands"
    )

    # Encrypt command
    encrypt_parser = subparsers.add_parser(
        "encrypt", help="Encrypt environment variables."
    )
    encrypt_parser.add_argument(
        "--source-file",
        type=str,
        default=".env",
        help="The source file containing environment variables.",
    )
    encrypt_parser.add_argument(
        "--key-name",
        type=str,
        required=True,
        help="The name of the key to use for encryption.",
    )

    # Decrypt command
    decrypt_parser = subparsers.add_parser(
        "decrypt", help="Decrypt environment variables."
    )
    decrypt_parser.add_argument(
        "--source-file",
        type=str,
        default=".env",
        help="The source file containing encrypted data.",
    )
    decrypt_parser.add_argument(
        "--key-name",
        type=str,
        required=True,
        help="The name of the key to use for decryption.",
    )
    decrypt_parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="The output file path. Use '-' or '/dev/stdout' for stdout.",
    )


    # Rotate key command
    rotate_parser = subparsers.add_parser(
        "rotate-key", help="Rotate the encryption key."
    )
    rotate_parser.add_argument(
        "--source-file",
        type=str,
        default=".env",
        help="The source file containing encrypted data.",
    )
    rotate_parser.add_argument(
        "--old-key-name",
        type=str,
        required=True,
        help="The name of the old encryption key.",
    )
    rotate_parser.add_argument(
        "--new-key-name",
        type=str,
        required=True,
        help="The name of the new encryption key.",
    )

    # Generate key command
    generate_parser = subparsers.add_parser(
        "generate-key", help="Generate a new encryption key."
    )
    generate_parser.add_argument(
        "--key-name",
        type=str,
        required=True,
        help="The name of the key to generate.",
    )
    generate_parser.add_argument(
        "--key-length",
        type=int,
        default=32,
        help="The length of the key in bytes (default: 32).",
    )

    # List keys command
    list_parser = subparsers.add_parser(
        "list-keys", help="List all available encryption keys."
    )

    list_parser.add_argument(
        "--key-directory",
        type=str,
        default="keys",
        help="The directory where keys are stored (default: 'keys').",
    )

    # Delete key command
    delete_parser = subparsers.add_parser(
        "delete-key", help="Delete an encryption key."
    )
    delete_parser.add_argument(
        "--key-name",
        type=str,
        required=True,
        help="The name of the key to delete.",
    )

    return parser.parse_args()


def main():
    """
    Main function to execute based on parsed arguments.
    """
    args = parse_arguments()
    key_manager = KeyManager()

    if args.command == "encrypt":
        key_name = args.key_name
        try:
            key = key_manager.load_key(key_name)
        except Exception as e:
            logger.error(f"Failed to load key '{key_name}': {e}")
            sys.exit(1)
        encrypt_env(args.source_file, key)

    if args.command == "decrypt":
        key_name = args.key_name
        try:
            key = key_manager.load_key(key_name)
        except Exception as e:
            logger.error(f"Failed to load key '{key_name}': {e}")
            sys.exit(1)
        decrypt_env(args.source_file, key, output=args.output)


    elif args.command == "rotate-key":
        old_key_name = args.old_key_name
        new_key_name = args.new_key_name
        rotate_key(key_manager, args.source_file, old_key_name, new_key_name)

    elif args.command == "generate-key":
        key_name = args.key_name
        key_length = args.key_length
        try:
            key_manager.generate_key(key_name, key_length)
        except Exception as e:
            logger.error(f"Failed to generate key '{key_name}': {e}")
            sys.exit(1)

    elif args.command == "list-keys":
        keys = key_manager.list_keys()
        if keys:
            logger.info("Available keys:")
            for name, path in keys.items():
                logger.info(f" - {name}: {path}")
        else:
            logger.info("No keys found.")

    elif args.command == "delete-key":
        key_name = args.key_name
        try:
            key_manager.delete_key(key_name)
        except Exception as e:
            logger.error(f"Failed to delete key '{key_name}': {e}")
            sys.exit(1)

    else:
        logger.error("Unknown command.")
        sys.exit(1)


if __name__ == "__main__":
    main()

    # Sample usage:
    # Generate Key: python envcrypt.py generate-key --key-name mykey --key-length 32
    # Encrypt: python envcrypt.py encrypt --source-file .env --key-name mykey
    # Decrypt: python envcrypt.py decrypt --source-file .env --key-name mykey
    # Rotate Key: python envcrypt.py rotate-key --source-file .env --old-key-name oldkey --new-key-name newkey
    # List Keys: python envcrypt.py list-keys
    # Delete Key: python envcrypt.py delete-key --key-name mykey
    # Decrypt to stdout: python envcrypt.py decrypt --source-file .env --key-name mykey --output -
