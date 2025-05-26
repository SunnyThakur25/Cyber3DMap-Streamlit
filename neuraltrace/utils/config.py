# neuraltrace/utils/config.py
"""
Configuration management for NeuralTrace.
Loads secrets from .env.
"""
import os
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import json

class Config:
    """Loads and manages NeuralTrace configuration."""
    
    def __init__(self):
        """Initialize Config with .env and encrypted config."""
        load_dotenv()
        self._decrypt_config()
    
    def _decrypt_config(self):
        """Decrypt config.json.enc."""
        try:
            with open("config.key", "rb") as key_file:
                key = key_file.read()
            fernet = Fernet(key)
            with open("config.json.enc", "rb") as f:
                encrypted = f.read()
            config = json.loads(fernet.decrypt(encrypted))
            os.environ.update(config)
        except Exception as e:
            raise Exception(f"Config decryption failed: {e}")

    @property
    def xai_api_key(self) -> str:
        return os.getenv("XAI_API_KEY")

    @property
    def x_api_key(self) -> str:
        return os.getenv("X_API_KEY")

    @property
    def whois_api_key(self) -> str:
        return os.getenv("WHOIS_API_KEY")

    @property
    def brightdata_auth(self) -> str:
        return os.getenv("BRIGHTDATA_AUTH")

    @property
    def db_url(self) -> str:
        return os.getenv("DB_URL")

    @property
    def aws_access_key(self) -> str:
        return os.getenv("AWS_ACCESS_KEY")

    @property
    def aws_secret_key(self) -> str:
        return os.getenv("AWS_SECRET_KEY")

    @property
    def aws_s3_bucket(self) -> str:
        return os.getenv("AWS_S3_BUCKET")

    @property
    def dataset_path(self) -> str:
        return os.getenv("DATASET_PATH", "/data/cicids2017.csv")