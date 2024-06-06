# MoClon/__init__.py
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Ensure config is imported and set
from MoClon.config import Config