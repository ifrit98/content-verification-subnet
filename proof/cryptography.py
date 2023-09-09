import hashlib
import gnupg
import secrets
import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm


def generate_password(seed, length=12):
    # Convert the seed to string
    seed_str = str(seed)
    
    # Hash the string representation using SHA-256
    hashed = hashlib.sha256(seed_str.encode()).hexdigest()
    
    # Use the hash to generate a password
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    
    return password


def hash256(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


def hash512(content: str) -> str:
    return hashlib.sha512(content.encode()).hexdigest()


def generate_keypair(name: str, email: str, passphrase: str) -> pgpy.PGPKey:
    """
    Generate a PGP keypair.

    Args:
    - name (str): The name associated with the key.
    - email (str): The email associated with the key.
    - passphrase (str): The passphrase to protect the private key.

    Returns:
    - pgpy.PGPKey: The generated key.
    """
    # Generate a primary key
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)

    # Add a user ID to the key
    uid = pgpy.PGPUID.new(name, email=email)
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA512],
                ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES128],
                compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])

    # Protect the key with the passphrase
    key.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

    return key


def sign_content_with_new_keypair(content: str, passphrase: str = None, seed: int = 1337) -> (str, str):
    """
    Sign the content using the private key.

    Args:
    - content (str): The content to sign.
    - passphrase (str): The passphrase for the private key.

    Returns:
    - tuple: The cleartext signature and the public key.
    """
    # Generate a primary key
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)

    # Add a user ID to the key
    uid = pgpy.PGPUID.new('Test User', email='test@example.com')
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA512],
                ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES128],
                compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])

    # TODO: use a real passphrase and get it from the env variables or terminal input
    # For not just generate a throw-away passphrase
    if passphrase is None:
        passphrase = generate_password(seed)

    # Protect the key with the passphrase
    key.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

    # Unlock the key to sign data
    with key.unlock(passphrase):
        # Create a cleartext signature
        cleartext_signature = pgpy.PGPMessage.new(content, cleartext=True)
        cleartext_signature |= key.sign(cleartext_signature, hash=HashAlgorithm.SHA256)

    return str(cleartext_signature), str(key.pubkey)


def sign_with_key(key: pgpy.PGPKey, content: str, passphrase: str) -> str:
    """
    Sign the content using the provided private key.

    Args:
    - key (pgpy.PGPKey): The private key to use for signing.
    - content (str): The content to sign.
    - passphrase (str): The passphrase for the private key.

    Returns:
    - str: The cleartext signature.
    """
    # Unlock the key to sign data
    with key.unlock(passphrase):
        # Create a cleartext signature
        cleartext_signature = pgpy.PGPMessage.new(content, cleartext=True)
        cleartext_signature |= key.sign(cleartext_signature, hash=HashAlgorithm.SHA256)

    return str(cleartext_signature)


def generate_keypair(name: str, email: str, passphrase: str) -> pgpy.PGPKey:
    """
    Generate a PGP keypair.

    Args:
    - name (str): The name associated with the key.
    - email (str): The email associated with the key.
    - passphrase (str): The passphrase to protect the private key.

    Returns:
    - pgpy.PGPKey: The generated key.
    """
    # Generate a primary key
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)

    # Add a user ID to the key
    uid = pgpy.PGPUID.new(name, email=email)
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA512],
                ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES128],
                compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])

    # Protect the key with the passphrase
    key.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

    return key


def verify_pgpy_with_content(content: str, signature: str, pubkey: str) -> bool:
    """
    Verify the cleartext signature of the content using the provided public key.

    Args:
    - signature (str): The cleartext signature string.
    - content (str): The content string.
    - pubkey (str): The public key string.

    Returns:
    - bool: True if the signature is valid, False otherwise.
    """
    # Load the public key
    public_key, _ = pgpy.PGPKey.from_blob(pubkey)

    # Load the signature
    signature_obj = pgpy.PGPSignature.from_blob(signature)

    # Convert the content to bytes if it's not
    if not isinstance(content, bytes):
        content = content.encode('utf-8')

    # Verify the signature using the content and public key
    return public_key.verify(content, signature_obj)


def verify_pgpy(content: str, signature: str, pubkey: str) -> bool:
    """
    Verify the cleartext signature of the content using the provided public key.

    Args:
    - signature (str): The cleartext signature string.
    - content (str): The content string.
    - pubkey (str): The public key string.

    Returns:
    - bool: True if the signature is valid, False otherwise.
    """
    # Load the public key
    public_key, _ = pgpy.PGPKey.from_blob(pubkey)

    # Load the cleartext signature
    cleartext_signature = pgpy.PGPMessage.from_blob(signature)

    # Verify the cleartext signature
    return public_key.verify(cleartext_signature)    


def verify_gnupg(signature: str, content: str, pubkey: str) -> bool:
    """
    Verify the signature of the content using the provided public key.

    Args:
    - signature (str): The signature string.
    - content (str): The content string.
    - pubkey (str): The public key string.

    Returns:
    - bool: True if the signature is valid, False otherwise.
    """
    raise NotImplementedError


sign = sign_content
verify = verify_pgpy_with_content
hash = hash256
