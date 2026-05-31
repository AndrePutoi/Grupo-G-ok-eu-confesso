from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models.models import User
from app.crypto.rsa_keys import generate_rsa_keypair, encrypt_private_key
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import secrets
import string
import json

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')
ph = PasswordHasher()

VALID_KEY_SIZES   = {2048, 3072, 4096}
VALID_HASH_ALGOS  = {'SHA256', 'SHA384', 'SHA512'}
VALID_CIPHER_MODES = {'CBC', 'CTR'}


def generate_password(length=16):
    """Gera uma password aleatória de 16 caracteres alfanuméricos.
    Usa secrets para garantir aleatoriedade criptograficamente segura."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """GET  — mostra o formulário de registo com opções de segurança.
    POST — gera password, par de chaves RSA e guarda o utilizador na BD."""
    if request.method == 'POST':
        email       = request.form.get('email', '').strip() or None
        key_size    = int(request.form.get('key_size', 2048))
        hash_algo   = request.form.get('hash_algo', 'SHA256')
        cipher_mode = request.form.get('cipher_mode', 'CBC')

        # Validação dos parâmetros de segurança
        if key_size not in VALID_KEY_SIZES:
            key_size = 2048
        if hash_algo not in VALID_HASH_ALGOS:
            hash_algo = 'SHA256'
        if cipher_mode not in VALID_CIPHER_MODES:
            cipher_mode = 'CBC'

        password      = generate_password()
        password_hash = ph.hash(password)

        public_pem, private_pem = generate_rsa_keypair(key_size=key_size)
        encrypted_key = encrypt_private_key(private_pem, password, cipher_mode=cipher_mode)

        user = User(
            email=email,
            password_hash=password_hash,
            public_key=public_pem.decode('utf-8'),
            private_key_encrypted=json.dumps(encrypted_key),
            key_size=key_size,
            hash_algo=hash_algo,
            cipher_mode=cipher_mode
        )
        db.session.add(user)
        db.session.commit()

        return render_template('register.html',
            password=password,
            public_key=public_pem.decode('utf-8'),
            private_key=json.dumps(encrypted_key, indent=2),
            key_size=key_size,
            hash_algo=hash_algo,
            cipher_mode=cipher_mode
        )

    return render_template('register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """GET  — mostra o formulário de login.
    POST — verifica a password contra todos os utilizadores (não há nome de utilizador)."""
    if request.method == 'POST':
        password = request.form.get('password')
        users = User.query.all()

        for user in users:
            try:
                ph.verify(user.password_hash, password)
                if ph.check_needs_rehash(user.password_hash):
                    user.password_hash = ph.hash(password)
                    db.session.commit()
                login_user(user)
                return redirect(url_for('auth.dashboard'))
            except VerifyMismatchError:
                continue

        flash('Password incorreta.', 'danger')

    return render_template('login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    """Termina a sessão do utilizador e redireciona para o login."""
    logout_user()
    return redirect(url_for('auth.login'))


@auth_bp.route('/dashboard')
@login_required
def dashboard():
    """Painel principal — apenas acessível com sessão ativa."""
    return render_template('dashboard.html')
