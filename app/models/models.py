from app import db
from flask_login import UserMixin
from datetime import datetime

# Cria a Tabela de Usuários, onde armazenamos o hash da senha, as chaves RSA e a data de criação
class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    password_hash = db.Column(db.String(256), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key_encrypted = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    messages_sent = db.relationship('Message', backref='sender', lazy=True)

# Cria a Tabela de Mensagens, onde armazenamos o remetente, destinatário, hash do código, texto cifrado e HMAC
class Message(db.Model):
    __tablename__ = 'messages'

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    recipient_email = db.Column(db.String(256), nullable=False)
    code_hash = db.Column(db.String(256), nullable=False)  # hash do código, nunca o código em claro
    ciphertext = db.Column(db.Text, nullable=False)
    mac = db.Column(db.String(256), nullable=True)  # HMAC opcional (bónus)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    receipt = db.relationship('Receipt', backref='message', lazy=True)

#
class Receipt(db.Model):
    __tablename__ = 'receipts'

    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=False)
    signed_receipt = db.Column(db.Text, nullable=False)  # assinatura RSA do recibo
    confirmed_at = db.Column(db.DateTime, default=datetime.utcnow)