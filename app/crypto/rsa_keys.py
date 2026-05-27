from cryptography.hazmat.primitives.asymmetric import rsa, padding as apad
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.exceptions import InvalidSignature
import os


def generate_rsa_keypair(key_size=2048):
    """Gera par de chaves RSA. Devolve (public_key_pem, private_key_pem) em bytes."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return public_pem, private_pem  # ambos em bytes, prontos a guardar


def encrypt_private_key(private_key_pem: bytes, password: str) -> dict:
    """Cifra a chave privada com AES-256-CBC usando PBKDF2 para derivar a chave.
    Devolve dicionário com sal, iv e chave cifrada (tudo em hex)."""
    sal = os.urandom(16)
    iv  = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,           # 256 bits
        salt=sal,
        iterations=600_000
    )
    aes_key = kdf.derive(password.encode())

    padder = padding.PKCS7(128).padder()
    padded = padder.update(private_key_pem) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    enc = cipher.encryptor()
    encrypted = enc.update(padded) + enc.finalize()

    return {
        "sal": sal.hex(),
        "iv": iv.hex(),
        "encrypted_key": encrypted.hex()
    }


def decrypt_private_key(encrypted_data: dict, password: str) -> bytes:
    """Decifra a chave privada. Devolve private_key_pem em bytes."""
    sal       = bytes.fromhex(encrypted_data["sal"])
    iv        = bytes.fromhex(encrypted_data["iv"])
    encrypted = bytes.fromhex(encrypted_data["encrypted_key"])

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=sal,
        iterations=600_000
    )
    aes_key = kdf.derive(password.encode())

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(encrypted) + dec.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def load_private_key(private_key_pem: bytes):
    """Converte PEM em objeto de chave privada (para usar internamente)."""
    return serialization.load_pem_private_key(private_key_pem, password=None)


def load_public_key(public_key_pem: bytes):
    """Converte PEM em objeto de chave pública (para usar internamente)."""
    return serialization.load_pem_public_key(public_key_pem)


def sign_receipt(receipt_data: str, private_key_pem: bytes) -> str:
    """Assina o recibo com SHA256withRSA. Devolve assinatura em hex."""
    private_key = load_private_key(private_key_pem)
    signature = private_key.sign(
        receipt_data.encode(),
        apad.PKCS1v15(),
        hashes.SHA256()
    )
    return signature.hex()


def verify_signature(receipt_data: str, signature_hex: str, public_key_pem: bytes) -> bool:
    """Verifica a assinatura do recibo. Devolve True ou False."""
    public_key = load_public_key(public_key_pem)
    try:
        public_key.verify(
            bytes.fromhex(signature_hex),
            receipt_data.encode(),
            apad.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False