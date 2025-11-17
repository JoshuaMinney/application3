#from . import db
#from flask_login import UserMixin
#from sqlalchemy.sql import func

#class Note(db.Model):
 #   id = db.Column(db.Integer, primary_key=True)
  #  date = db.Column(db.String(1000))
   # date = db.Column(db.DateTime(timezone=True), default=func.now())
    #identifier = db.Column(db.Integer, db.ForeignKey('user.id'))

#class user(db.Model, UserMixin):
 #   id = db.Column(db.Integer, primary_key=True)
  #  password = db.Column(db.String(100))
   # email = db.Column(db.String(100), unique=True)
    #notes = db.relationship('Note')