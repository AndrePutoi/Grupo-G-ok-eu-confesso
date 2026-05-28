from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from app import db
from app.models.models import Message
from app.crypto.aes_email import (
    generate_code,
    encrypt_email_body,
    hash_code,
    create_hmac
)
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

sender_bp = Blueprint('sender', __name__, url_prefix='/send')


@sender_bp.route('/', methods=['GET', 'POST'])
@login_required
def send_message():
    if request.method == 'POST':
        recipient_email = request.form.get('recipient_email')
        subject = request.form.get('subject')
        body = request.form.get('body')

        # Validação básica
        if not recipient_email or not subject or not body:
            flash('Preenche todos os campos.', 'error')
            return render_template('sender/send.html')

        # 1. Gera o código aleatório de 32 chars hexadecimal (Pessoa 3)
        code = generate_code()

        # 2. Cifra o corpo do e-mail com AES-256-CTR (Pessoa 3)
        ciphertext = encrypt_email_body(body, code)

        # 3. Gera o HMAC para integridade (Pessoa 3 - bónus)
        mac = create_hmac(ciphertext, code)

        # 4. Faz hash do código para guardar na BD (nunca guardamos o código em claro)
        code_hash = hash_code(code)

        # 5. Guarda a mensagem na base de dados
        message = Message(
            sender_id=current_user.id,
            recipient_email=recipient_email,
            code_hash=code_hash,
            ciphertext=ciphertext,
            mac=mac
        )
        db.session.add(message)
        db.session.commit()

        # 6. Envia o e-mail com o corpo cifrado + código + link
        success = send_email(
            recipient=recipient_email,
            subject=subject,
            ciphertext=ciphertext,
            code=code
        )

        if success:
            flash('E-mail enviado com sucesso!', 'success')
        else:
            flash('Mensagem guardada mas erro ao enviar e-mail.', 'warning')

        return redirect(url_for('sender.send_message'))

    return render_template('sender/send.html')


def send_email(recipient, subject, ciphertext, code):
    """Envia o e-mail com o corpo cifrado e instruções para o destinatário."""
    try:
        system_url = os.getenv('SYSTEM_URL', 'http://localhost:5000')

        msg = MIMEMultipart()
        msg['From'] = os.getenv('MAIL_FROM', 'sistema@ok-eu-confesso.pt')
        msg['To'] = recipient
        msg['Subject'] = subject

        body = f"""Se quiser ler este e-mail, aceda ao sistema:
{system_url}/receive/

e confirme a receção com o código: {code}

--- MENSAGEM CIFRADA (não é legível sem o código) ---
{ciphertext}
--- FIM DA MENSAGEM CIFRADA ---
"""
        msg.attach(MIMEText(body, 'plain'))

        smtp_host = os.getenv('MAIL_HOST', 'localhost')
        smtp_port = int(os.getenv('MAIL_PORT', 1025))

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.sendmail(msg['From'], recipient, msg.as_string())

        return True

    except Exception as e:
        print(f'Erro ao enviar e-mail: {e}')
        return False