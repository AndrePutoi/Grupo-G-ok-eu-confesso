# Funções que a Pessoa 2 vai implementar:

def generate_rsa_keypair():
    # gera par de chaves RSA
    # devolve (public_key, private_key)
    pass

def encrypt_private_key(private_key, password):
    # cifra a chave privada com AES-256-CBC derivado da password
    # devolve private_key_encrypted
    pass

def decrypt_private_key(private_key_encrypted, password):
    # decifra a chave privada
    # devolve private_key
    pass

def sign_receipt(receipt_data, private_key):
    # assina o recibo com SHA256withRSA
    # devolve assinatura
    pass

def verify_signature(receipt_data, signature, public_key):
    # verifica a assinatura do recibo
    # devolve True ou False
    pass