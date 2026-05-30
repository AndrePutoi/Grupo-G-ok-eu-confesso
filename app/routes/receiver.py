from flask import Blueprint, render_template, request, flash
from app.models.models import Message, Receipt
from app.crypto.aes_email import verify_code, decrypt_email_body_verified
from app.crypto.rsa_keys import decrypt_private_key, sign_receipt, verify_signature
from app import db
import json

receiver_bp = Blueprint('receiver', __name__, url_prefix='/receive')


#GET  — mostra o formulário para inserir o código, chave privada e ciphertext
#POST — processa os dados, decifra a mensagem e gera o recibo assinado
@receiver_bp.route('/', methods=['GET', 'POST'])
def receive_message():
    decrypted_body = None

    if request.method == 'POST':
        code              = request.form.get('code', '').strip()
        password          = request.form.get('password', '').strip()
        private_key_json  = request.form.get('private_key', '').strip()
        ciphertext        = request.form.get('ciphertext', '').strip()
        confirmed_receipt = request.form.get('confirm_receipt')
        confirmed_read    = request.form.get('confirm_read')

        #Validação básica de campos obrigatórios
        if not code or not password or not private_key_json or not ciphertext:
            flash('Preenche todos os campos obrigatórios.', 'error')
            return render_template('receiver/receive.html')

        #Verifica se o utilizador confirmou receção e leitura
        if confirmed_receipt != 'yes' or confirmed_read != 'yes':
            flash('Tens de confirmar a receção e que vais ler a mensagem.', 'warning')
            return render_template('receiver/receive.html')

        #Procura a mensagem na BD pelo ciphertext e verifica o código
        message = Message.query.filter_by(ciphertext=ciphertext).first()
        if not message or not verify_code(code, message.code_hash):
            flash('Código ou mensagem inválidos.', 'error')
            return render_template('receiver/receive.html')

        #Desencripta a chave privada RSA do destinatário
        try:
            encrypted_key_data = json.loads(private_key_json)
            private_key_pem = decrypt_private_key(encrypted_key_data, password)
        except Exception:
            flash('Chave privada ou password incorretos.', 'error')
            return render_template('receiver/receive.html')

        #Decifra o corpo do e-mail verificando o HMAC para garantir a integridade
        try:
            decrypted_body = decrypt_email_body_verified(
                ciphertext,
                code,
                message.mac
            )
        except ValueError as e:
            flash(f'Erro ao decifrar: {e}', 'error')
            return render_template('receiver/receive.html')

        #Gera e guarda o recibo assinado digitalmente
        try:
            receipt_text = f"Mensagem {message.id} recebida e lida."
            signed = sign_receipt(receipt_text, private_key_pem)

            receipt = Receipt(
                message_id=message.id,
                signed_receipt=signed
            )
            db.session.add(receipt)
            db.session.commit()

            flash('Mensagem decifrada com sucesso! Recibo gerado.', 'success')

        except Exception as e:
            print(f'Erro ao gerar recibo: {e}')
            flash('Mensagem decifrada mas erro ao gerar recibo.', 'warning')

    return render_template('receiver/receive.html', decrypted_body=decrypted_body)


#GET  — mostra o formulário para inserir o ID da mensagem e a chave pública.
#POST — verifica se existe recibo e valida a assinatura digital do destinatário.
@receiver_bp.route('/verify', methods=['GET', 'POST'])
def verify_receipt():
    result = None

    if request.method == 'POST':
        message_id     = request.form.get('message_id', '').strip()
        public_key_pem = request.form.get('public_key', '').strip()

        if not message_id or not public_key_pem:
            flash('Preenche todos os campos.', 'error')
            return render_template('receiver/verify.html', result=result)

        #Procura o recibo na base de dados
        receipt = Receipt.query.filter_by(message_id=message_id).first()

        if not receipt:
            flash('Nenhum recibo encontrado para esta mensagem.', 'error')
            return render_template('receiver/verify.html', result=result)

        #Reconstrói o texto do recibo para verificar a assinatura
        #Verifica a assinatura do recibo
        receipt_text = f"Mensagem {message_id} recebida e lida."
        is_valid = verify_signature(
            receipt_text,
            receipt.signed_receipt,
            public_key_pem.encode()
        )

        if is_valid:
            result = 'válida'
            flash('Assinatura válida — a mensagem foi lida!', 'success')
        else:
            result = 'inválida'
            flash('Assinatura inválida!', 'error')

    return render_template('receiver/verify.html', result=result)