from flask import Blueprint, render_template, request, flash
from app.models.models import Message, Receipt
from app.crypto.aes_email import verify_code, decrypt_email_body_verified
from app.crypto.rsa_keys import decrypt_private_key, sign_receipt, verify_signature
from app import db
import json

receiver_bp = Blueprint('receiver', __name__, url_prefix='/receive')


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

        # 1. Validação básica
        if not code or not password or not private_key_json or not ciphertext:
            flash('Preenche todos os campos obrigatórios.', 'error')
            return render_template('receiver/receive.html')

        # 2. Verifica se o utilizador confirmou receção e leitura
        if confirmed_receipt != 'yes' or confirmed_read != 'yes':
            flash('Tens de confirmar a receção e que vais ler a mensagem.', 'warning')
            return render_template('receiver/receive.html')

        # 3. Verifica se o código existe na base de dados
        message = Message.query.filter_by(ciphertext=ciphertext).first()
        if not message or not verify_code(code, message.code_hash):
            flash('Código ou mensagem inválidos.', 'error')
            return render_template('receiver/receive.html')

        # 4. Desencripta a chave privada com a password (Pessoa 2)
        # A chave privada é colada como JSON: {"sal":..., "iv":..., "encrypted_key":...}
        try:
            encrypted_key_data = json.loads(private_key_json)
            private_key_pem = decrypt_private_key(encrypted_key_data, password)
        except Exception:
            flash('Chave privada ou password incorretos.', 'error')
            return render_template('receiver/receive.html')

        # 5. Decifra o corpo do e-mail verificando o HMAC (Pessoa 3)
        try:
            decrypted_body = decrypt_email_body_verified(
                ciphertext,
                code,
                message.mac
            )
        except ValueError as e:
            flash(f'Erro ao decifrar: {e}', 'error')
            return render_template('receiver/receive.html')

        # 6. Gera e guarda o recibo assinado digitalmente (Pessoa 2)
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


@receiver_bp.route('/verify', methods=['GET', 'POST'])
def verify_receipt():
    result = None

    if request.method == 'POST':
        message_id     = request.form.get('message_id', '').strip()
        public_key_pem = request.form.get('public_key', '').strip()

        if not message_id or not public_key_pem:
            flash('Preenche todos os campos.', 'error')
            return render_template('receiver/verify.html', result=result)

        # Procura o recibo na base de dados
        receipt = Receipt.query.filter_by(message_id=message_id).first()

        if not receipt:
            flash('Nenhum recibo encontrado para esta mensagem.', 'error')
            return render_template('receiver/verify.html', result=result)

        # Verifica a assinatura do recibo (Pessoa 2)
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