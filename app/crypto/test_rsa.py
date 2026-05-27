from app.crypto.rsa_keys import (
    generate_rsa_keypair,
    encrypt_private_key,
    decrypt_private_key,
    sign_receipt,
    verify_signature
)

# 1. Gerar chaves
print("A gerar chaves RSA...")
public_pem, private_pem = generate_rsa_keypair()
print("Chave pública:")
print(public_pem.decode())
print("Chave privada:")
print(private_pem.decode())

# 2. Cifrar e decifrar a chave privada
print("\nA cifrar chave privada...")
password = "abcd1234efgh5678"
encrypted = encrypt_private_key(private_pem, password)
print("Dados cifrados:", encrypted)

print("\nA decifrar chave privada...")
decrypted = decrypt_private_key(encrypted, password)
print("Decifrada com sucesso:", decrypted == private_pem)

# 3. Testar com password errada
print("\nA tentar decifrar com password errada...")
try:
    decrypt_private_key(encrypted, "passworderrada123")
    print("ERRO — devia ter falhado!")
except Exception as e:
    print("Correto — falhou como esperado:", type(e).__name__)

# 4. Assinar e verificar recibo
print("\nA assinar recibo...")
texto = "Eu, teste@email.com, confirmo que li a mensagem ABC123 em 2025-01-01."
assinatura = sign_receipt(texto, private_pem)
print("Assinatura:", assinatura[:40], "...")

print("\nA verificar assinatura correta...")
resultado = verify_signature(texto, assinatura, public_pem)
print("Válida:", resultado)

print("\nA verificar assinatura com texto alterado...")
resultado2 = verify_signature("texto diferente", assinatura, public_pem)
print("Válida (devia ser False):", resultado2)