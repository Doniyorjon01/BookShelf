from sqlalchemy import func

from . import db


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128), unique=True, nullable=False)
    email = db.Column(db.String(128), unique=True, nullable=False)
    phone = db.Column(db.String(512), unique=True, nullable=False)
    password = db.Column(db.String(512), nullable=False)
    # balance = db.Column(db.Float, nullable=False)
    # create_at = db.Column(db.Date, default=func.now())


class Transfer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_username = db.Column(db.String(128),nullable=False)
    to_username = db.Column(db.String(128),nullable=False)
    balance = db.Column(db.Float, nullable=False)
    create_at = db.Column(db.Date, default=func.now())

class Books(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), nullable=False)