from pymongo import MongoClient
import pandas as pd

client = MongoClient('mongodb://localhost:27017')
db = 'langchainAgent'

def query_db(collection: str, query: dict):
    collection = client.get_database(db).get_collection(collection)
    return pd.DataFrame(list(collection.find(query)))

def insert_docs_to_db(docs: dict, collection: str):
    collection = client.get_database(db).get_collection(collection)
    collection.insert_many(docs)
