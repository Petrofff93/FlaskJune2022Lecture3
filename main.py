import enum

from decouple import config
from flask import Flask, request
from flask_migrate import Migrate
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from marshmallow import Schema, fields

app = Flask(__name__)

db_user = config('DB_USER')
db_password = config('DB_PASSWORD')
db_port = config('DB_PORT')
db_name = config('DB_NAME')

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{db_user}:{db_password}@localhost:{db_port}/{db_name}'

db = SQLAlchemy(app)
api = Api(app)
migrate = Migrate(app, db)


class UserSignInSchema(Schema):
    email = fields.Email()
    password = fields.Str()
    full_name = fields.Str()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.Text)
    created_on = db.Column(db.DateTime, server_default=func.now())
    updated_on = db.Column(db.DateTime, onupdate=func.now())


class ColorEnum(enum.Enum):
    pink = 'pink'
    black = 'black'
    white = 'white'
    yellow = 'yellow'


class SizeEnum(enum.Enum):
    xs = 'XS'
    s = 'S'
    m = 'M'
    l = 'L'
    xl = 'XL'
    xxl = 'XXL'


class Clothes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    color = db.Column(
        db.Enum(ColorEnum),
        default=ColorEnum.white,
        nullable=False
    )
    photo = db.Column(db.String(255), nullable=False)
    created_on = db.Column(db.DateTime, server_default=func.now())
    updated_on = db.Column(db.DateTime, onupdate=func.now())


class UserSignIn(Resource):
    def post(self):
        data = request.get_json()
        user = User(**data)
        db.session.add(user)
        db.session.commit()
        

api.add_resource(UserSignIn, "/register/")

if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
