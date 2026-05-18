# Funções que a Pessoa 3 vai implementar:

def generate_code():
    # gera código aleatório de 32 chars hexadecimal
    # devolve code (string)
    pass

def derive_key(code):
    # deriva chave de 256 bits com PBKDF2
    # devolve key (bytes)
    pass

def encrypt_email_body(body, code):
    # cifra o corpo do email com AES-256-CTR
    # devolve ciphertext
    pass

def decrypt_email_body(ciphertext, code):
    # decifra o corpo do email
    # devolve body (string)
    pass