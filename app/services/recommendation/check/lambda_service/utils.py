import logging
from typing import Dict, List, Any

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('lambda_recommendations.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)