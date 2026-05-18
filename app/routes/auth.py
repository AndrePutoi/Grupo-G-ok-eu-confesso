from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required
from app import db
from app.models.models import User
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import secrets
import string

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')
ph = PasswordHasher()

def generate_password(length=16):
    alphabet = string.ascii_letters + string.digits
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        # Verificar se já existe na BD
        exists = False
        for user in User.query.all():
            try:
                ph.verify(user.password_hash, password) #  Com 62^16 possibilidades a probabilidade de colisão é tão baixa que é irrelevante. Mas vamos garantir que não haja colisões.
                exists = True
                break
            except VerifyMismatchError:
                continue
        if not exists:
            return password


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        password = generate_password()
        password_hash = ph.hash(password)

        user = User(
            password_hash=password_hash,
            public_key="placeholder_pessoa2",
            private_key_encrypted="placeholder_pessoa2"
        )
        db.session.add(user)
        db.session.commit()

        flash(f'A tua password é: {password} — Guarda-a, não será mostrada novamente!', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')
        users = User.query.all()

        for user in users:
            try:
                ph.verify(user.password_hash, password)
                login_user(user)
                return redirect(url_for('auth.dashboard'))
            except VerifyMismatchError:
                continue

        flash('Password incorreta.', 'danger')

    return render_template('login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth_bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')