from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from config import Config

db = SQLAlchemy()
login_manager = LoginManager()

@login_manager.user_loader
def load_user(user_id):
    from app.models.models import User
    return User.query.get(int(user_id))

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    from app.routes.auth import auth_bp
    from app.routes.sender import sender_bp
    from app.routes.receiver import receiver_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(sender_bp)
    app.register_blueprint(receiver_bp)

    with app.app_context():
        from app.models import models
        db.create_all()

    return app