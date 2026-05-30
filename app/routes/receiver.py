from flask import Blueprint, render_template, request, flash
from app.models.models import Message, Receipt, User
from app.crypto.aes_email import decrypt_email_body_verified, hash_code
from app.crypto.rsa_keys import decrypt_private_key, sign_receipt, verify_signature
from app import db
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

receiver_bp = Blueprint('receiver', __name__, url_prefix='/receive')

ph = PasswordHasher()


def _notify_sender(sender_email: str, message_id: int, read_at):
    """Envia e-mail de notificação ao emissor quando o recibo é gerado."""
    try:
        system_url = os.getenv('SYSTEM_URL', 'http://localhost:5000')
        msg = MIMEMultipart()
        msg['From'] = os.getenv('MAIL_FROM', 'sistema@ok-eu-confesso.pt')
        msg['To'] = sender_email
        msg['Subject'] = f'[OK-Eu-CONFESSO] Mensagem #{message_id} foi lida'

        body = (
            f"A tua mensagem #{message_id} foi lida e o recibo foi assinado digitalmente.\n\n"
            f"Data/Hora: {read_at.strftime('%Y-%m-%d %H:%M UTC')}\n\n"
            f"Podes verificar a validade do recibo em:\n{system_url}/receive/verify\n"
        )
        msg.attach(MIMEText(body, 'plain'))

        smtp_host = os.getenv('MAIL_HOST', 'localhost')
        smtp_port = int(os.getenv('MAIL_PORT', 1025))
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.sendmail(msg['From'], sender_email, msg.as_string())
    except Exception as e:
        print(f'Erro ao notificar emissor: {e}')


def _find_user_by_password(password: str):
    """Devolve o User cuja password corresponde, ou None."""
    for user in User.query.all():
        try:
            ph.verify(user.password_hash, password)
            return user
        except VerifyMismatchError:
            continue
    return None


# GET  — mostra o formulário para inserir o código e a password
# POST — processa os dados, decifra a mensagem e gera o recibo assinado
@receiver_bp.route('/', methods=['GET', 'POST'])
def receive_message():
    decrypted_body = None
    receipt_id = None

    if request.method == 'POST':
        ciphertext       = request.form.get('ciphertext', '').strip()
        code             = request.form.get('code', '').strip()
        password         = request.form.get('password', '').strip()
        private_key_json = request.form.get('private_key', '').strip()
        confirmed_receipt = request.form.get('confirm_receipt')
        confirmed_read    = request.form.get('confirm_read')

        if not ciphertext or not code or not password or not private_key_json:
            flash('Preenche todos os campos obrigatórios.', 'error')
            return render_template('receiver/receive.html')

        if confirmed_receipt != 'yes' or confirmed_read != 'yes':
            flash('Tens de confirmar a receção e que vais ler a mensagem.', 'warning')
            return render_template('receiver/receive.html')

        # Autentica o utilizador pela password
        user = _find_user_by_password(password)
        if not user:
            flash('Password incorreta.', 'error')
            return render_template('receiver/receive.html')

        # Procura a mensagem pelo hash do código
        code_hash = hash_code(code)
        message = Message.query.filter_by(code_hash=code_hash).first()
        if not message:
            flash('Código inválido ou mensagem não encontrada.', 'error')
            return render_template('receiver/receive.html')

        # Verifica se já existe recibo para esta mensagem
        existing_receipt = Receipt.query.filter_by(message_id=message.id).first()
        if existing_receipt:
            flash('Esta mensagem já foi lida e o recibo já foi gerado.', 'warning')
            return render_template('receiver/receive.html')

        # Decifra a chave privada fornecida pelo utilizador
        try:
            encrypted_key_data = json.loads(private_key_json)
            private_key_pem = decrypt_private_key(encrypted_key_data, password)
        except Exception:
            flash('Chave privada ou password incorretos.', 'error')
            return render_template('receiver/receive.html')

        # Decifra o corpo do e-mail verificando o HMAC
        try:
            decrypted_body = decrypt_email_body_verified(
                ciphertext,
                code,
                message.mac
            )
        except ValueError as e:
            flash(f'Erro ao decifrar: {e}', 'error')
            return render_template('receiver/receive.html')

        # Gera e guarda o recibo assinado digitalmente
        try:
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc)
            receipt_text = (
                f"Mensagem {message.id} recebida e lida "
                f"em {now.strftime('%Y-%m-%dT%H:%M:%SZ')}."
            )
            signed = sign_receipt(receipt_text, private_key_pem, hash_algo=user.hash_algo)

            receipt = Receipt(
                message_id=message.id,
                signed_receipt=signed,
                signer_public_key=user.public_key,
                hash_algo=user.hash_algo
            )
            db.session.add(receipt)
            db.session.commit()

            receipt_id = message.id
            flash('Mensagem decifrada com sucesso! Recibo gerado.', 'success')

            # Notifica o emissor por e-mail se tiver e-mail registado
            sender = User.query.get(message.sender_id)
            if sender and sender.email:
                _notify_sender(sender.email, message.id, now)

        except Exception:
            flash('Mensagem decifrada mas erro ao gerar recibo.', 'warning')

    return render_template('receiver/receive.html',
                           decrypted_body=decrypted_body,
                           receipt_id=receipt_id)


# GET  — mostra o formulário para inserir o ID da mensagem e a chave pública
# POST — verifica se existe recibo e valida a assinatura digital do destinatário
@receiver_bp.route('/verify', methods=['GET', 'POST'])
def verify_receipt():
    result = None

    if request.method == 'POST':
        message_id = request.form.get('message_id', '').strip()

        if not message_id:
            flash('Preenche o ID da mensagem.', 'error')
            return render_template('receiver/verify.html', result=result)

        message = Message.query.get(message_id)
        if not message:
            flash('Mensagem não encontrada.', 'error')
            return render_template('receiver/verify.html', result=result)

        receipt = Receipt.query.filter_by(message_id=message_id).first()
        if not receipt:
            flash('Nenhum recibo encontrado — a mensagem ainda não foi lida.', 'error')
            return render_template('receiver/verify.html', result=result)

        confirmed_at = receipt.confirmed_at.strftime('%Y-%m-%dT%H:%M:%SZ')
        receipt_text = (
            f"Mensagem {message_id} recebida e lida "
            f"em {confirmed_at}."
        )
        is_valid = verify_signature(
            receipt_text,
            receipt.signed_receipt,
            receipt.signer_public_key.encode(),
            hash_algo=receipt.hash_algo or 'SHA256'
        )

        result = {
            'status': 'lido' if is_valid else 'inválido',
            'message_id': message_id,
            'recipient_email': message.recipient_email,
            'timestamp': receipt.confirmed_at.strftime('%Y-%m-%d %H:%M UTC'),
            'signature_valid': is_valid
        }

        if is_valid:
            flash('Assinatura válida — a mensagem foi lida!', 'success')
        else:
            flash('Assinatura inválida!', 'error')

    return render_template('receiver/verify.html', result=result)
