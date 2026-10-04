import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database", "app.db")

connection = sqlite3.connect(DB_PATH)
connection.row_factory = sqlite3.Row