from app.crypto.aes_email import (
    generate_code,
    encrypt_email_body,
    decrypt_email_body,
    decrypt_email_body_verified,
    hash_code,
    verify_code,
    create_hmac,
    verify_hmac,
)

body = "Esta é uma mensagem secreta de teste."

print("--- Teste funcional ---")

code = generate_code()
ciphertext = encrypt_email_body(body, code)
code_hash = hash_code(code)
mac = create_hmac(ciphertext, code)

decrypted = decrypt_email_body(ciphertext, code)
decrypted_verified = decrypt_email_body_verified(ciphertext, code, mac)

print("Código:", code)
print("Tamanho do código:", len(code))
print("Ciphertext:", ciphertext)
print("Mensagem original:", body)
print("Mensagem decifrada:", decrypted)
print("Mensagem decifrada com verificação:", decrypted_verified)

print("Código tem 32 caracteres?", len(code) == 32)
print("Ciphertext é diferente da mensagem original?", ciphertext != body)
print("Código válido?", verify_code(code, code_hash))
print("HMAC válido?", verify_hmac(ciphertext, code, mac))
print("Teste passou?", decrypted == body and decrypted_verified == body)

print("\n--- Teste de aleatoriedade ---")

ciphertext_2 = encrypt_email_body(body, code)

print("Ciphertext 1:", ciphertext)
print("Ciphertext 2:", ciphertext_2)
print("Cifrar a mesma mensagem duas vezes gera resultado diferente?", ciphertext != ciphertext_2)

print("\n--- Testes de segurança ---")

wrong_code = "codigo_errado"

print("Código errado é aceite?", verify_code(wrong_code, code_hash))
print("HMAC com código errado é válido?", verify_hmac(ciphertext, wrong_code, mac))

tampered_ciphertext = ciphertext[:-1] + ("A" if ciphertext[-1] != "A" else "B")
print("HMAC com ciphertext alterado é válido?", verify_hmac(tampered_ciphertext, code, mac))

try:
    decrypt_email_body_verified(tampered_ciphertext, code, mac)
    print("Mensagem alterada foi decifrada sem erro.")
except Exception as e:
    print("Mensagem alterada rejeitada:", e)

try:
    decrypt_email_body_verified(ciphertext, wrong_code, mac)
    print("Mensagem com código errado foi decifrada sem erro.")
except Exception as e:
    print("Código errado rejeitado:", e)



# --- Teste funcional ---
# Código: 071965db43a6e0a60b7a660980ba17a9
# Tamanho do código: 32
# Ciphertext: eyJhbGciOiJBRVMtMjU2LUNUUiIsImNpcGhlcnRleHQiOiI5QlpUWi1RWFFadFltQVh1SERFSjdFU2ZneE0xNm5kcDRNWXdCOWNIVU5IWU1qcTN4V009IiwiaXRlcmF0aW9ucyI6NDAwMDAwLCJrZGYiOiJQQktERjItSE1BQy1TSEEyNTYiLCJub25jZSI6Ill5bzkwb0dtckdUZEJpeDNSZEZUVGc9PSIsInNhbHQiOiJIdW1oOHJpTEljOXhHMlYwT3ZIRDhRPT0iLCJ2IjoxfQ==
# Mensagem original: Esta é uma mensagem secreta de teste.
# Mensagem decifrada: Esta é uma mensagem secreta de teste.
# Mensagem decifrada com verificação: Esta é uma mensagem secreta de teste.
# Código tem 32 caracteres? True
# Ciphertext é diferente da mensagem original? True
# Código válido? True
# HMAC válido? True
# Teste passou? True

# --- Teste de aleatoriedade ---
# Ciphertext 1: eyJhbGciOiJBRVMtMjU2LUNUUiIsImNpcGhlcnRleHQiOiI5QlpUWi1RWFFadFltQVh1SERFSjdFU2ZneE0xNm5kcDRNWXdCOWNIVU5IWU1qcTN4V009IiwiaXRlcmF0aW9ucyI6NDAwMDAwLCJrZGYiOiJQQktERjItSE1BQy1TSEEyNTYiLCJub25jZSI6Ill5bzkwb0dtckdUZEJpeDNSZEZUVGc9PSIsInNhbHQiOiJIdW1oOHJpTEljOXhHMlYwT3ZIRDhRPT0iLCJ2IjoxfQ==
# Ciphertext 2: eyJhbGciOiJBRVMtMjU2LUNUUiIsImNpcGhlcnRleHQiOiI4MzZ0WmNVMkdFSk85SU5QcmNsYzRVSVNfaWpyUDh1ZElwcnEzcURPcjFwV1JvQ0hVWWs9IiwiaXRlcmF0aW9ucyI6NDAwMDAwLCJrZGYiOiJQQktERjItSE1BQy1TSEEyNTYiLCJub25jZSI6ImNjcTBxREpNZW85MUM3UENZcndBTGc9PSIsInNhbHQiOiJJVVY2WUpoX3R5YVBVcTFseGQyUm9BPT0iLCJ2IjoxfQ==
# Cifrar a mesma mensagem duas vezes gera resultado diferente? True

# --- Testes de segurança ---
# Código errado é aceite? False
# HMAC com código errado é válido? False
# HMAC com ciphertext alterado é válido? False
# Mensagem alterada rejeitada: HMAC inválido: a mensagem pode ter sido alterada.
# Código errado rejeitado: HMAC inválido: a mensagem pode ter sido alterada.

#Este output mostra que o módulo de encriptação está a funcionar corretamente. Primeiro, é gerado um código secreto aleatório com 32 caracteres,
#que será usado para criar a chave criptográfica. O ciphertext corresponde à mensagem já cifrada, ou seja, a mensagem original foi transformada
#num conteúdo ilegível. De seguida, o teste confirma que a mensagem decifrada é igual à mensagem original, tanto usando a função normal de 
# decifra como a função mais segura, que verifica o HMAC antes de decifrar.

# As verificações seguintes mostram que o código tem o tamanho esperado, que o ciphertext é diferente da mensagem original, 
# que o código introduzido é válido e que o HMAC também é válido. Como todos estes resultados deram True, o teste funcional passou.

# No teste de aleatoriedade, a mesma mensagem foi cifrada duas vezes com o mesmo código, mas gerou dois ciphertexts diferentes. 
# Isto é esperado e positivo, porque o sistema usa valores aleatórios como salt e nonce, evitando que mensagens iguais produzam sempre o mesmo
# resultado cifrado.

# Nos testes de segurança, o sistema rejeitou corretamente um código errado, rejeitou um HMAC criado com código errado e também detetou uma 
# alteração no ciphertext. Por fim, quando se tentou decifrar uma mensagem alterada ou com código errado, o sistema bloqueou a operação e 
# apresentou erro. Isto confirma que o módulo não só cifra e decifra mensagens, como também consegue detetar alterações ou tentativas de 
# acesso inválidas.
