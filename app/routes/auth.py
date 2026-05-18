from flask import Blueprint, render_template, redirect, url_for, request, flash

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    # TODO: lógica de registo
    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    # TODO: lógica de login
    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    # TODO: logout
    return redirect(url_for('auth.login'))