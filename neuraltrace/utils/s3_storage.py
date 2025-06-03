# neuraltrace/utils/s3_storage.py
"""
AWS S3 storage management for NeuralTrace.
Handles telemetry and report storage.
"""
import asyncio
import logging
import json
import boto3

logger = logging.getLogger(__name__)

class S3Storage:
    """Manages AWS S3 storage operations."""
    
    def __init__(self, access_key: str, secret_key: str, bucket: str):
        """
        Initialize S3Storage.
        
        Args:
            access_key (str): AWS access key.
            secret_key (str): AWS secret key.
            bucket (str): S3 bucket name.
        """
        self.client = boto3.client(
            "s3",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key
        )
        self.bucket = bucket

    async def upload_json(self, data: Dict, key: str):
        """
        Upload JSON data to S3.
        
        Args:
            data (Dict): Data to upload.
            key (str): S3 object key.
        """
        try:
            self.client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=json.dumps(data)
            )
            logger.info(f"Uploaded to S3: {key}")
        except Exception as e:
            logger.error(f"S3 upload failed: {e}")

    async def get_json(self, key: str) -> Dict:
        """
        Retrieve JSON data from S3.
        
        Args:
            key (str): S3 object key.
            
        Returns:
            Dict: Retrieved data.
        """
        try:
            response = self.client.get_object(Bucket=self.bucket, Key=key)
            return json.loads(response["Body"].read())
        except Exception as e:
            logger.error(f"S3 retrieval failed: {e}")
            return {}

    async def upload_file(self, filename: str, key: str):
        """
        Upload file to S3.
        
        Args:
            filename (str): Local file path.
            key (str): S3 object key.
        """
        try:
            self.client.upload_file(filename, self.bucket, key)
            logger.info(f"Uploaded file to S3: {key}")
        except Exception as e:
            logger.error(f"S3 file upload failed: {e}")