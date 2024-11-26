from pymongo import MongoClient

def create_collection(coll_name):
    client = MongoClient('mongodb+srv://mongouser:BigBallsBouncing@cluster0.nfi83.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
    db = client.WashDB
    # Drop the collection if it already exists (optional, for testing)
    if coll_name in db.list_collection_names():
        db[coll_name].drop()

    result = db.create_collection(coll_name, validator={
        "$jsonSchema": {
            "bsonType": "object",
            "required": [
                "username",
                "encaccnumber",
                "enccvv",
                "encsortcode",
                "status",
                "timestamp",
                "house number",
                "address",
                "citytown",
                "postcode",
                "country",
                "email"
            ],
            "properties": {
                "username": {
                    "bsonType": "string",
                    "minLength": 1,
                    "maxLength": 50,
                    "description": "must be a string representing the username and is required, between 1 and 50 characters"
                },
                "products": {
                    "bsonType": "string",
                    "description": "id of the object inside mongodb"
                },
                "encaccnumber": {
                    "bsonType": "string",
                    "description": "must be a string representing the encrypted account number and is required"
                },
                "enccvv": {
                    "bsonType": "string",
                    "description": "must be a string representing the encrypted CVV and is required"
                },
                "encsortcode": {
                    "bsonType": "string",
                    "description": "must be a string representing the encrypted sort code and is required"
                },
                "status": {
                    "bsonType": "string",
                    "enum": ["Left the warehouse", "Out for delivery", "Dispatched to courier", "Order confirmed"],
                    "description": "must be a string representing the order status and is required"
                },
                "timestamp": {
                    "bsonType": "string",
                    "description": "must be a string representing the timestamp and is required"
                },
                "house_number": {
                    "bsonType": "string",
                    "description": "must be a string representing the house number and is required"
                },
                "address": {
                    "bsonType": "string",
                    "description": "must be a string representing the address and is required"
                },
                "citytown": {
                    "bsonType": "string",
                    "description": "must be a string representing the city or town and is required"
                },
                "postcode": {
                    "bsonType": "string",
                    "description": "must be a string representing the postcode and is required"
                },
                "country": {
                    "bsonType": "string",
                    "description": "must be a string representing the country and is required"
                },
                "email": {
                    "bsonType": "string",
                    "description": "must be a string representing the email and is required"
                }
            },
            "additionalProperties": True
        }
    })
    print(f"Collection '{coll_name}' created with validation schema.")

if __name__ == '__main__':
    create_collection('Orders')