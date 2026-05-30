from cryptography.hazmat.primitives.asymmetric import rsa, padding as apad
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.exceptions import InvalidSignature
import os
import secrets

SUPPORTED_HASHES = {
    'SHA256': hashes.SHA256,
    'SHA384': hashes.SHA384,
    'SHA512': hashes.SHA512,
}


def _get_hash(hash_algo: str):
    if hash_algo not in SUPPORTED_HASHES:
        raise ValueError(f"Hash não suportado: {hash_algo}")
    return SUPPORTED_HASHES[hash_algo]()


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
    return public_pem, private_pem


def encrypt_private_key(private_key_pem: bytes, password: str, cipher_mode: str = 'CBC') -> dict:
    """Cifra a chave privada com AES-256-CBC ou AES-256-CTR usando PBKDF2.
    Devolve dicionário com sal, iv/nonce e chave cifrada (tudo em hex)."""
    sal = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=sal,
        iterations=600_000
    )
    aes_key = kdf.derive(password.encode())

    if cipher_mode == 'CTR':
        nonce = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce))
        enc = cipher.encryptor()
        encrypted = enc.update(private_key_pem) + enc.finalize()
        return {
            'mode': 'CTR',
            'sal': sal.hex(),
            'iv': nonce.hex(),
            'encrypted_key': encrypted.hex()
        }
    else:
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(private_key_pem) + padder.finalize()
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        enc = cipher.encryptor()
        encrypted = enc.update(padded) + enc.finalize()
        return {
            'mode': 'CBC',
            'sal': sal.hex(),
            'iv': iv.hex(),
            'encrypted_key': encrypted.hex()
        }


def decrypt_private_key(encrypted_data: dict, password: str) -> bytes:
    """Decifra a chave privada. Suporta CBC e CTR. Devolve private_key_pem em bytes."""
    sal       = bytes.fromhex(encrypted_data['sal'])
    iv        = bytes.fromhex(encrypted_data['iv'])
    encrypted = bytes.fromhex(encrypted_data['encrypted_key'])
    mode      = encrypted_data.get('mode', 'CBC')

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=sal,
        iterations=600_000
    )
    aes_key = kdf.derive(password.encode())

    if mode == 'CTR':
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv))
        dec = cipher.decryptor()
        return dec.update(encrypted) + dec.finalize()
    else:
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        dec = cipher.decryptor()
        padded = dec.update(encrypted) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()


def load_private_key(private_key_pem: bytes):
    return serialization.load_pem_private_key(private_key_pem, password=None)


def load_public_key(public_key_pem: bytes):
    return serialization.load_pem_public_key(public_key_pem)


def sign_receipt(receipt_data: str, private_key_pem: bytes, hash_algo: str = 'SHA256') -> str:
    """Assina o recibo com RSA + hash configurável. Devolve assinatura em hex."""
    private_key = load_private_key(private_key_pem)
    signature = private_key.sign(
        receipt_data.encode(),
        apad.PKCS1v15(),
        _get_hash(hash_algo)
    )
    return signature.hex()


def verify_signature(receipt_data: str, signature_hex: str, public_key_pem: bytes, hash_algo: str = 'SHA256') -> bool:
    """Verifica a assinatura do recibo. Devolve True ou False."""
    public_key = load_public_key(public_key_pem)
    try:
        public_key.verify(
            bytes.fromhex(signature_hex),
            receipt_data.encode(),
            apad.PKCS1v15(),
            _get_hash(hash_algo)
        )
        return True
    except InvalidSignature:
        return False
