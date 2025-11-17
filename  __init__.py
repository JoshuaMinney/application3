from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path

db = SQLAlchemy()

DB_NAME = "Database.db"

def create():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite////{DB_NAME}'
    db.innit_app(app)


    from . import dblayout
    database(app)

    return app

def database(app):
    if not path.exists('APPLICATION3/' + DB_NAME):
        db.create_all(app=app)
        print('Database has been built')
