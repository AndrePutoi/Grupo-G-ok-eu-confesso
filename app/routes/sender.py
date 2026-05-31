from flask import Blueprint, render_template, request, flash
from flask_login import login_required, current_user
from app import db
from app.models.models import Message
from app.crypto.aes_email import (
    generate_code,
    encrypt_email_body,
    hash_code,
    create_hmac
)
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

ph = PasswordHasher()

sender_bp = Blueprint('sender', __name__, url_prefix='/send')


#GET  — mostra o formulário para escrever a mensagem.
#POST — processa o envio: cifra a mensagem, guarda na BD e envia o e-mail.
@sender_bp.route('/', methods=['GET', 'POST'])
@login_required
def send_message():
    if request.method == 'POST':
        password       = request.form.get('password', '').strip()
        recipient_email = request.form.get('recipient_email')
        subject = request.form.get('subject')
        body = request.form.get('body')

        #Validação básica de campos obrigatórios
        if not password or not recipient_email or not subject or not body:
            flash('Preenche todos os campos.', 'error')
            return render_template('sender/send.html')

        # Verifica a password antes de qualquer operação (requisito 3 do enunciado)
        try:
            ph.verify(current_user.password_hash, password)
        except VerifyMismatchError:
            flash('Password incorreta.', 'error')
            return render_template('sender/send.html')

        #Gera o código aleatório de 32 chars hexadecimal para enviar ao destinatário
        code = generate_code()

        #Cifra o corpo do e-mail com AES-256-CTR usando o código como chave
        ciphertext = encrypt_email_body(body, code)

        #Gera o HMAC para integridade usando o código como chave e o ciphertext como mensagem
        mac = create_hmac(ciphertext, code)

        #Faz hash do código para guardar na BD
        code_hash = hash_code(code)

        #Guarda a mensagem na base de dados 
        message = Message(
            sender_id=current_user.id,
            recipient_email=recipient_email,
            subject=subject,
            code_hash=code_hash,
            ciphertext=ciphertext,
            mac=mac
        )
        db.session.add(message)
        db.session.commit()

        #Envia o e-mail ao destinatário com o ciphertext, o código e o ID da mensagem
        success = send_email(
            recipient=recipient_email,
            subject=subject,
            ciphertext=ciphertext,
            code=code,
            message_id=message.id
        )

        if success:
            flash('E-mail enviado com sucesso!', 'success')
        else:
            flash('Mensagem guardada mas erro ao enviar e-mail.', 'warning')

        return render_template('sender/send.html', message_id=message.id)

    return render_template('sender/send.html')


def send_email(recipient, subject, ciphertext, code, message_id):
    """Envia o e-mail com o corpo cifrado e instruções para o destinatário."""
    try:
        system_url = os.getenv('SYSTEM_URL', 'http://localhost:5000')

        msg = MIMEMultipart()
        msg['From'] = os.getenv('MAIL_FROM', 'sistema@ok-eu-confesso.pt')
        msg['To'] = recipient
        msg['Subject'] = subject

        body = f"""Se quiser ler este e-mail, aceda ao sistema:
{system_url}/receive/

e confirme a receção com:
  ID da mensagem : {message_id}
  Código         : {code}

--- MENSAGEM CIFRADA (não é legível sem o código) ---
{ciphertext}
--- FIM DA MENSAGEM CIFRADA ---
"""
        msg.attach(MIMEText(body, 'plain'))

        smtp_host = os.getenv('MAIL_HOST', 'localhost')
        smtp_port = int(os.getenv('MAIL_PORT', 1025))

        #Liga ao servidor SMTP e envia o e-mail
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.sendmail(msg['From'], recipient, msg.as_string())

        return True

    except Exception as e:
        print(f'Erro ao enviar e-mail: {e}')
        return False
