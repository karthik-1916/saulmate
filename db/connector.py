# db/connector.py

import mysql.connector
import json

def get_connection():
    with open("db/db_config.json") as f:
        config = json.load(f)
    return mysql.connector.connect(
        host=config["host"],
        user=config["user"],
        password=config["password"],
        database=config["database"]
    )
