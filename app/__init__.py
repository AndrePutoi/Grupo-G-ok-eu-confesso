from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from config import Config

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    # Registar os blueprints (módulos de rotas)
    from app.routes.auth import auth_bp
    from app.routes.sender import sender_bp
    from app.routes.receiver import receiver_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(sender_bp)
    app.register_blueprint(receiver_bp)

    # Criar tabelas na BD se não existirem
    with app.app_context():
        db.create_all()

    return app