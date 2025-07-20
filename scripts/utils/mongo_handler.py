from pymongo import MongoClient
import pandas as pd
import os

mongo_uri = os.getenv('MONGO_URI', 'mongodb://db:27017/langchainAgent')

client = MongoClient(mongo_uri.replace("langchainAgent", ""))
db = 'langchainAgent'


def query_db(collection: str, query: dict, one_element=False):
    collection = client.get_database(db).get_collection(collection)
    if one_element:
        return list(collection.find(query, {"_id": 0}))
    return pd.DataFrame(list(collection.find(query, {"_id": 0})))

def insert_docs_to_db(docs: list, collection: str):
    collection = client.get_database(db).get_collection(collection)
    try:
        collection.insert_many(docs)
    except Exception as e:
        print(e, "Failed to insert docs2mongoDB. ", docs)
