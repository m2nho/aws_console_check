import boto3
from typing import Dict, List, Any
import logging

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('s3_recommendations.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def get_s3_recommendations(buckets: List[Dict], aws_access_key: str, aws_secret_key: str, region: str) -> List[Dict]:
    """S3 버킷 추천 사항 수집"""
    logger.info("Starting S3 recommendations analysis")
    try:
        recommendations = []
        
        # 데이터 구조 확인 및 로깅
        logger.info(f"Received data type: {type(buckets)}")
        
        # buckets가 리스트인 경우
        if isinstance(buckets, list):
            bucket_list = buckets
        # buckets가 딕셔너리이고 'buckets' 키가 있는 경우
        elif isinstance(buckets, dict) and 'buckets' in buckets:
            bucket_list = buckets['buckets']
        else:
            logger.error(f"Unexpected data type: {type(buckets)}")
            return []
        
        logger.info(f"Processing {len(bucket_list)} buckets")
        
        for bucket in bucket_list:
            bucket_name = bucket.get('name', 'unknown')
            logger.debug(f"Processing bucket: {bucket_name}")
            
            try:
                # 1. 퍼블릭 액세스 검사
                if bucket.get('public_access'):
                    recommendations.append({
                        'service': 'S3',
                        'resource': bucket_name,
                        'message': "S3 버킷의 퍼블릭 액세스 설정을 검토하세요.",
                        'severity': '높음',
                        'problem': "S3 버킷이 퍼블릭 액세스 가능 상태입니다.",
                        'impact': "데이터 유출 및 보안 위험이 있습니다.",
                        'benefit': "퍼블릭 액세스를 차단하여 데이터 보안을 강화할 수 있습니다.",
                        'steps': [
                            "AWS 콘솔에서 S3 서비스로 이동합니다.",
                            f"버킷 {bucket_name}을 선택합니다.",
                            "'권한' 탭으로 이동합니다.",
                            "'퍼블릭 액세스 차단' 설정을 활성화합니다."
                        ]
                    })
                
                # 2. 버저닝 검사
                if not bucket.get('versioning'):
                    recommendations.append({
                        'service': 'S3',
                        'resource': bucket_name,
                        'message': "S3 버킷의 버저닝 활성화를 검토하세요.",
                        'severity': '중간',
                        'problem': "S3 버킷에 버저닝이 활성화되어 있지 않습니다.",
                        'impact': "실수로 인한 데이터 손실 위험이 있습니다.",
                        'benefit': "버저닝을 활성화하여 데이터 보호 및 복구 기능을 강화할 수 있습니다.",
                        'steps': [
                            "AWS 콘솔에서 S3 서비스로 이동합니다.",
                            f"버킷 {bucket_name}을 선택합니다.",
                            "'속성' 탭으로 이동합니다.",
                            "'버전 관리' 설정을 활성화합니다."
                        ]
                    })
                
                # 3. 암호화 검사
                if not bucket.get('encryption'):
                    recommendations.append({
                        'service': 'S3',
                        'resource': bucket_name,
                        'message': "S3 버킷의 기본 암호화 설정을 검토하세요.",
                        'severity': '중간',
                        'problem': "S3 버킷에 기본 암호화가 설정되어 있지 않습니다.",
                        'impact': "저장 데이터의 보안이 취약할 수 있습니다.",
                        'benefit': "기본 암호화를 활성화하여 데이터 보안을 강화할 수 있습니다.",
                        'steps': [
                            "AWS 콘솔에서 S3 서비스로 이동합니다.",
                            f"버킷 {bucket_name}을 선택합니다.",
                            "'속성' 탭으로 이동합니다.",
                            "'기본 암호화' 설정을 활성화합니다."
                        ]
                    })
                
                # 4. 라이프사이클 규칙 검사
                if not bucket.get('lifecycle_rules'):
                    recommendations.append({
                        'service': 'S3',
                        'resource': bucket_name,
                        'message': "S3 버킷의 라이프사이클 규칙 설정을 검토하세요.",
                        'severity': '낮음',
                        'problem': "S3 버킷에 라이프사이클 규칙이 설정되어 있지 않습니다.",
                        'impact': "불필요한 스토리지 비용이 발생할 수 있습니다.",
                        'benefit': "라이프사이클 규칙을 설정하여 비용을 최적화할 수 있습니다.",
                        'steps': [
                            "AWS 콘솔에서 S3 서비스로 이동합니다.",
                            f"버킷 {bucket_name}을 선택합니다.",
                            "'관리' 탭으로 이동합니다.",
                            "'라이프사이클 규칙'을 생성합니다."
                        ]
                    })
                
                # 5. 태그 관리 검사
                if not bucket.get('tags'):
                    recommendations.append({
                        'service': 'S3',
                        'resource': bucket_name,
                        'message': "S3 버킷의 태그 관리를 검토하세요.",
                        'severity': '낮음',
                        'problem': "S3 버킷에 태그가 설정되어 있지 않습니다.",
                        'impact': "리소스 관리 및 비용 할당이 어려울 수 있습니다.",
                        'benefit': "태그를 설정하여 리소스 관리 및 비용 추적을 개선할 수 있습니다.",
                        'steps': [
                            "AWS 콘솔에서 S3 서비스로 이동합니다.",
                            f"버킷 {bucket_name}을 선택합니다.",
                            "'속성' 탭으로 이동합니다.",
                            "'태그' 섹션에서 태그를 추가합니다."
                        ]
                    })
                
            except Exception as e:
                logger.error(f"Error processing bucket {bucket_name}: {str(e)}")
                continue
        
        logger.info(f"Found {len(recommendations)} recommendations")
        return recommendations
    except Exception as e:
        logger.error(f"Error in get_s3_recommendations: {str(e)}")
        return []