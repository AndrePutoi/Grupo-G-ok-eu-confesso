# # Funções que a Pessoa 3 vai implementar:
#
# def generate_code():
#     # gera código aleatório de 32 chars hexadecimal
#     # devolve code (string)
#     pass
#
# def derive_key(code):
#     # deriva chave de 256 bits com PBKDF2
#     # devolve key (bytes)
#     pass
#
# def encrypt_email_body(body, code):
#     # cifra o corpo do email com AES-256-CTR
#     # devolve ciphertext
#     pass
#
# def decrypt_email_body(ciphertext, code):
#     # decifra o corpo do email
#     # devolve body (string)
#     pass

"""
Pessoa 3 — Encriptação do corpo do e-mail.

Este módulo gera um código secreto, deriva internamente uma chave segura com PBKDF2,
cifra a mensagem com AES-256-CTR e permite decifrá-la apenas com o código correto.
Também guarda/verifica o hash do código e usa HMAC-SHA256 para detetar alterações
na mensagem cifrada.

Uso direto pela Pessoa 4:

No envio:
- generate_code()
- encrypt_email_body(body, code)
- hash_code(code)
- create_hmac(ciphertext, code)

Na receção:
- verify_code(code, message.code_hash)
- decrypt_email_body_verified(message.ciphertext, code, message.mac)

A função decrypt_email_body_verified() já verifica o HMAC antes de decifrar.

A Pessoa 1 só precisa de garantir campos na base de dados para:
ciphertext, code_hash e mac.

As funções começadas por "_" são auxiliares internas e não devem ser chamadas
diretamente noutros ficheiros.
"""

import base64
import json
import secrets
import hashlib
import hmac as py_hmac

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


PBKDF2_ITERATIONS = 400_000
AES_KEY_SIZE = 32          # 32 bytes = 256 bits
SALT_SIZE = 16             # 128 bits | o salt é um valor aleatório, dessa forma 2 pessoas nao conseguem gerar a mesma chave
NONCE_SIZE = 16            # AES CTR usa bloco de 128 bits | faz o mesmo que o salt


def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8")


def _b64_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("utf-8"))


def generate_code() -> str:
    """
    Gera um código aleatório de 32 caracteres hexadecimais.

    Este código é enviado ao destinatário e usado para derivar a chave
    que cifra/decifra o corpo do email.
    """
    return secrets.token_hex(16)


def derive_key(code: str, salt: bytes, purpose: str = "encryption") -> bytes:
    """
    Deriva uma chave de 256 bits usando PBKDF2-HMAC-SHA256.

    O parâmetro 'purpose' permite separar chaves para usos diferentes:
    - encryption: AES-256-CTR
    - hmac: HMAC-SHA256
    """
    if not isinstance(code, str) or not code.strip():
        raise ValueError("O código não pode estar vazio.")

    if not isinstance(salt, (bytes, bytearray)) or len(salt) < SALT_SIZE:
        raise ValueError("O salt deve ter pelo menos 16 bytes.")

    purpose_bytes = purpose.encode("utf-8")
    full_salt = bytes(salt) + b":" + purpose_bytes

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=full_salt,
        iterations=PBKDF2_ITERATIONS,
    )

    return kdf.derive(code.encode("utf-8"))


def _pack_encrypted_data(data: dict) -> str:
    """
    Converte os dados da cifra para JSON e depois para base64.

    Assim conseguimos guardar tudo no campo ciphertext da base de dados:
    algoritmo, salt, nonce e texto cifrado.
    """
    json_data = json.dumps(data, separators=(",", ":"), sort_keys=True)
    return _b64_encode(json_data.encode("utf-8"))


def _unpack_encrypted_data(ciphertext_package: str) -> dict:
    """
    Lê o pacote base64 guardado no campo ciphertext e devolve o dicionário.
    """
    try:
        raw_json = _b64_decode(ciphertext_package).decode("utf-8")
        data = json.loads(raw_json)
    except Exception as exc:
        raise ValueError("Formato do ciphertext inválido.") from exc

    required_fields = {"v", "alg", "kdf", "iterations", "salt", "nonce", "ciphertext"}

    if not required_fields.issubset(data.keys()):
        raise ValueError("Ciphertext incompleto ou corrompido.")

    if data["alg"] != "AES-256-CTR":
        raise ValueError("Algoritmo não suportado.")

    return data


def encrypt_email_body(body: str, code: str) -> str:
    """
    Cifra o corpo do email com AES-256-CTR.

    Recebe:
        body: texto original do email
        code: código aleatório gerado por generate_code()

    Devolve:
        string base64 com salt + nonce + ciphertext
    """
    if not isinstance(body, str):
        raise ValueError("O corpo do email deve ser uma string.")

    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)

    key = derive_key(code, salt, purpose="encryption")

    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(nonce),
    )

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(body.encode("utf-8")) + encryptor.finalize()

    encrypted_data = {
        "v": 1,
        "alg": "AES-256-CTR",
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": PBKDF2_ITERATIONS,
        "salt": _b64_encode(salt),
        "nonce": _b64_encode(nonce),
        "ciphertext": _b64_encode(ciphertext),
    }

    return _pack_encrypted_data(encrypted_data)


def decrypt_email_body(ciphertext_package: str, code: str) -> str:
    """
    Decifra o corpo do email.

    Recebe:
        ciphertext_package: string gerada por encrypt_email_body()
        code: código inserido pelo destinatário

    Devolve:
        corpo original do email em texto claro
    """
    data = _unpack_encrypted_data(ciphertext_package)

    salt = _b64_decode(data["salt"])
    nonce = _b64_decode(data["nonce"])
    ciphertext = _b64_decode(data["ciphertext"])

    key = derive_key(code, salt, purpose="encryption")

    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(nonce),
    )

    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Código incorreto ou mensagem corrompida.") from exc


def hash_code(code: str) -> str:
    """
    Gera hash SHA-256 do código.

    Isto permite guardar apenas o hash na base de dados,
    nunca o código em claro.
    """
    if not isinstance(code, str) or not code.strip():
        raise ValueError("O código não pode estar vazio.")

    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def verify_code(code: str, stored_code_hash: str) -> bool:
    """
    Verifica se o código inserido corresponde ao hash guardado na BD.
    """
    if not stored_code_hash:
        return False

    calculated_hash = hash_code(code)

    return py_hmac.compare_digest(calculated_hash, stored_code_hash)


def create_hmac(ciphertext_package: str, code: str) -> str:
    """
    Bónus: cria um HMAC-SHA256 para garantir integridade.

    O HMAC permite detetar se o ciphertext foi alterado.
    """
    data = _unpack_encrypted_data(ciphertext_package)
    salt = _b64_decode(data["salt"])

    hmac_key = derive_key(code, salt, purpose="hmac")

    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(ciphertext_package.encode("utf-8"))

    return _b64_encode(h.finalize())


def verify_hmac(ciphertext_package: str, code: str, mac: str) -> bool:
    """
    Bónus: verifica se o HMAC guardado continua válido.
    """
    if not mac:
        return False

    try:
        expected_mac = create_hmac(ciphertext_package, code)
        return py_hmac.compare_digest(expected_mac, mac)
    except Exception:
        return False


def decrypt_email_body_verified(ciphertext_package: str, code: str, mac: str) -> str:
    """
    Decifra o corpo do email apenas depois de verificar o HMAC.

    Esta função é mais segura para ser usada no receiver.py,
    porque impede que uma mensagem alterada seja decifrada.
    """
    if not verify_hmac(ciphertext_package, code, mac):
        raise ValueError("HMAC inválido: a mensagem pode ter sido alterada.")

    return decrypt_email_body(ciphertext_package, code)
