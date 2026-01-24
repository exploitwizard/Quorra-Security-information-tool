from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)


def init_db(app):
    """
    Initialize the database properly with Flask app context
    """
    # Bind SQLAlchemy to Flask app
    db.init_app(app)

    with app.app_context():
        from app.models import QuorraUser, LogEntry, Alert, Attack, IPBlocklist

        # Create all tables
        db.create_all()

        # Create default Quorra user if not exists
        default_user = QuorraUser.query.filter_by(username='user-quorra').first()
        if not default_user:
            default_user = QuorraUser(username='user-quorra', is_admin=True)
            default_user.set_password('quorra@1000')
            db.session.add(default_user)
            db.session.commit()
            print("✅ Default Quorra user created")
