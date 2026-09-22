import os

from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))

load_dotenv(os.path.join(basedir, ".env"))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-secret-key")
    DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"
    PORT = int(os.environ.get("PORT", "5001"))
    DATABASE = os.path.join(basedir, "instance", "blindspot.db")