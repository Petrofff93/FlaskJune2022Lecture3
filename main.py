import enum
from functools import wraps
import phonenumbers

from decouple import config
from marshmallow_enum import EnumField
from flask import Flask, request
from flask_migrate import Migrate
from flask_restful import Api, Resource, abort
from flask_sqlalchemy import SQLAlchemy
from phonenumbers import NumberParseException
from sqlalchemy import func
from marshmallow import Schema, fields, ValidationError, validates
from password_strength import PasswordPolicy
from werkzeug.security import generate_password_hash

app = Flask(__name__)

db_user = config('DB_USER')
db_password = config('DB_PASSWORD')
db_port = config('DB_PORT')
db_name = config('DB_NAME')

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{db_user}:{db_password}@localhost:{db_port}/{db_name}'

db = SQLAlchemy(app)
api = Api(app)
migrate = Migrate(app, db)


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


# universal validation func
def validate_schema(schema_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            schema = schema_name()
            errors = schema.validate(request.get_json())
            if errors:
                abort(400, errors=errors)
            return f(*args, **kwargs)

        return decorated_function

    return decorator


# password input rules
policy = PasswordPolicy.from_names(
    uppercase=1,
    numbers=1,
    special=1,
    nonletters=1
)


# Schema class used to validate user's input
class UserSignInSchema(Schema):
    email = fields.Email(required=True)
    password = fields.Str(required=True)
    full_name = fields.Str(required=True)
    phone_number = fields.Str(required=True)

    @validates("full_name")
    def validate_name(self, name):
        try:
            first_name, last_name = name.split()
        except ValueError as ex:
            raise ValidationError("First and Last name are mandatory!")
        if len(first_name) < 3 or len(last_name) < 3:
            raise ValidationError("Each name should consist of at least 3 characters")

    @validates("password")
    def validate_password(self, password):
        errors = policy.test(password)
        if errors:
            raise ValidationError("Password does not meet requirements!")

    @validates("phone_number")
    def validate_phone_number(self, phone_number):
        number = f"{phone_number}"
        try:
            phone_number = phonenumbers.parse(number)
        except NumberParseException:
            raise ValidationError("Please enter valid phone number!")


class ClothesSchema(Schema):
    id = fields.Integer()
    name = fields.Str()
    color = EnumField(ColorEnum, by_value=True)
    size = EnumField(SizeEnum, by_value=True)
    created_on = fields.DateTime()


class UserResponseSchema(Schema):
    id = fields.Integer()
    full_name = fields.Str()
    clothes = fields.List(fields.Nested(ClothesSchema), many=True)


users_clothes = db.Table(
    "users_clothes",
    db.Model.metadata,
    db.Column("user_id", db.Integer, db.ForeignKey("user.id")),
    db.Column("clothes_id", db.Integer, db.ForeignKey("clothes.id")),
)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.Text)
    created_on = db.Column(db.DateTime, server_default=func.now())
    updated_on = db.Column(db.DateTime, onupdate=func.now())
    clothes = db.relationship("Clothes", secondary=users_clothes)


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


# creating the register form (password is hidden by password hashing)
class UserSignIn(Resource):
    @validate_schema(UserSignInSchema)
    def post(self):
        data = request.get_json()
        data['password'] = generate_password_hash(data['password'])
        user = User(**data)
        db.session.add(user)
        db.session.commit()
        return data


# creating the get request
class UserResource(Resource):
    def get(self, pk):
        user = User.query.filter_by(id=pk).first()
        return UserResponseSchema().dump(user)


# adding the resources as endpoints
api.add_resource(UserSignIn, "/register/")
api.add_resource(UserResource, "/users/<int:pk>/")

if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
