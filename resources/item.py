from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity

from models.item import ItemModel

BLANK_ERROR = "'{}' cannot be blank"
NAME_ALREADY_EXISTS = "An item with name '{}' already exists."
ERROR_INSERTING = "An error occurred inserting the item."
ITEM_NOT_FOUND = "Item not found"
ITEM_DELETED = "item deleted"


class Item(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument("price",
                        type=float,
                        required=True,
                        help=BLANK_ERROR.format("price")
                        )
    parser.add_argument("store_id",
                        type=int,
                        required=True,
                        help=BLANK_ERROR.format("store_id")
                        )

    @classmethod
    def get(cls, name: str):
        item = ItemModel.find_by_name(name)
        if item:
            return item.json()
        return {"message": ITEM_NOT_FOUND}, 404

    @classmethod
    @jwt_required(fresh=True)
    def post(cls, name: str):
        item = ItemModel.find_by_name(name)
        if item:
            return {"message": NAME_ALREADY_EXISTS.format(name)}, 400

        data = Item.parser.parse_args()
        new_item = ItemModel(name=name, **data)
        try:
            new_item.save_to_db()
        except:
            return {"message": ERROR_INSERTING}, 500

        return new_item.json(), 201

    @classmethod
    @jwt_required()
    def delete(cls, name: str):
        claims = get_jwt()
        if not claims["is_admin"]:
            return {"message": "Admin privilege required."}, 401

        item = ItemModel.find_by_name(name)
        if item:
            item.delete_from_db()
            return {"message": ITEM_DELETED}
        return {"message": ITEM_NOT_FOUND}

    @classmethod
    def put(cls, name: str):
        data = Item.parser.parse_args()
        item = ItemModel.find_by_name(name)

        if item is None:
            item = ItemModel(name, **data)
        else:
            item.price = data["price"]
        item.save_to_db()

        return item.json()


class ItemList(Resource):
    @classmethod
    @jwt_required(optional=True)
    def get(cls):
        user_id = get_jwt_identity()
        items = [item.json() for item in ItemModel.find_all()]
        if user_id:
            return {"Items": items}, 200
        return {
                   "items": [item["name"] for item in items],
                   "message": "More data available if you log in."
               }, 200
        # return {"items": list(map(lambda x: x.json(), items))}
