from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy

DB_NAME = "Database.db"

def create():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite///{DB_NAME}'
