from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    jwt_required,
    get_jwt
)
from flask_restful import reqparse, Resource

from blacklist import BLACKLIST
from models.user import UserModel


BLANK_ERROR = "'{}' cannot be blank"
USER_ALREADY_EXISTS = "A user with that username already exists."
CREATED_SUCCESSFULLY = "User created successfully"
USER_NOT_FOUND = "User not found"
USER_DELETED = "User deleted"
INVALID_CREDENTIALS = "Invalid credentials"
USER_LOGGED_OUT = "User '{}' successfully logged out."


_user_parser = reqparse.RequestParser()
_user_parser.add_argument("username",
                          type=str,
                          required=True,
                          help=BLANK_ERROR.format("username"))

_user_parser.add_argument("password",
                          type=str,
                          required=True,
                          help=BLANK_ERROR.format("password"))


class UserRegister(Resource):
    @classmethod
    def post(cls):
        data = _user_parser.parse_args()
        if UserModel.find_by_username(username=data["username"]):
            return {"message": USER_ALREADY_EXISTS}, 400
        else:
            user = UserModel(**data)
            user.save_to_db()
        return {"message": CREATED_SUCCESSFULLY}


class User(Resource):
    @classmethod
    def get(cls, user_id: int):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {"message": USER_NOT_FOUND}, 404
        return user.json()

    @classmethod
    def delete(cls, user_id: int):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {"message": USER_NOT_FOUND}, 404
        user.delete_from_db()
        return {"message": USER_DELETED}, 200


class UserLogin(Resource):
    @classmethod
    def post(cls):
        data = _user_parser.parse_args()

        user = UserModel.find_by_username(data["username"])
        if user and user.password == data["password"]:
            access_token = create_access_token(identity=user.id, fresh=True)
            refresh_token = create_refresh_token(user.id)
            return {
                       "access_token": access_token,
                       "refresh_token": refresh_token
                   }, 200
        return {"message": INVALID_CREDENTIALS}, 401


class UserLogout(Resource):
    @classmethod
    @jwt_required()
    def post(cls):
        jti = get_jwt()["jti"]  # jti is "JWT ID", a unique identifier for a JWT
        user_id = get_jwt_identity()
        BLACKLIST.add(jti)
        # print(BLACKLIST)
        return {"message": USER_LOGGED_OUT.format(user_id)}, 200


class TokenRefresh(Resource):
    @classmethod
    @jwt_required(refresh=True)
    def post(cls):
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user, fresh=False)
        return {"access_token": new_token}
