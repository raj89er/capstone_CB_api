
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from config import Config


app = Flask(__name__)

CORS(app)

app.config.from_object(Config)

# instance of SQLAlchemy with the app as an argument
db = SQLAlchemy(app)
# instance of Migrate with the app and db as arguments (migrating things in app to db)
migrate = Migrate(app, db)

from . import routes, models, auth

