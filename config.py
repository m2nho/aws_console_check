import os
from dotenv import load_dotenv
import re

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard-to-guess-string'
    AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
    
    # Validate AWS region format before using it
    aws_region = os.environ.get('AWS_DEFAULT_REGION')
    # AWS region format validation (e.g., us-east-1, ap-northeast-2)
    region_pattern = re.compile(r'^[a-z]{2}-[a-z]+-\d+$')
    
    if aws_region and region_pattern.match(aws_region):
        AWS_DEFAULT_REGION = aws_region
    else:
        AWS_DEFAULT_REGION = 'ap-northeast-2'  # Default to Seoul region
