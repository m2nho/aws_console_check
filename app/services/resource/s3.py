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

def get_s3_data(aws_access_key: str, aws_secret_key: str, region: str) -> Dict:
    """S3 버킷 데이터 수집"""
    logger.info("Starting S3 data collection")
    try:
        # S3 클라이언트 생성
        s3_client = boto3.client(
            's3',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        # 버킷 목록 가져오기
        response = s3_client.list_buckets()
        buckets = []
        
        logger.info(f"Found {len(response.get('Buckets', []))} S3 buckets")
        
        # 각 버킷에 대한 정보 수집
        for bucket in response.get('Buckets', []):
            bucket_name = bucket['Name']
            logger.debug(f"Processing bucket: {bucket_name}")
            
            # 기본 버킷 정보
            bucket_data = {
                'name': bucket_name,
                'creation_date': bucket['CreationDate'],
                'region': None,
                'public_access': False,
                'versioning': False,
                'encryption': False,
                'lifecycle_rules': [],
                'tags': {},
                'size': 0,
                'object_count': 0
            }
            
            # 버킷 리전 확인
            try:
                location = s3_client.get_bucket_location(Bucket=bucket_name)
                bucket_data['region'] = location.get('LocationConstraint') or 'us-east-1'
            except Exception as e:
                logger.error(f"Error getting bucket location for {bucket_name}: {str(e)}")
            
            # 퍼블릭 액세스 설정 확인
            try:
                public_access = s3_client.get_public_access_block(Bucket=bucket_name)
                bucket_data['public_access'] = not (
                    public_access['PublicAccessBlockConfiguration']['BlockPublicAcls'] and
                    public_access['PublicAccessBlockConfiguration']['BlockPublicPolicy'] and
                    public_access['PublicAccessBlockConfiguration']['IgnorePublicAcls'] and
                    public_access['PublicAccessBlockConfiguration']['RestrictPublicBuckets']
                )
            except Exception as e:
                # 퍼블릭 액세스 블록 설정이 없는 경우 잠재적으로 퍼블릭으로 간주
                logger.error(f"Error getting public access block for {bucket_name}: {str(e)}")
                bucket_data['public_access'] = True
            
            # 버저닝 설정 확인
            try:
                versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                bucket_data['versioning'] = versioning.get('Status') == 'Enabled'
            except Exception as e:
                logger.error(f"Error getting versioning for {bucket_name}: {str(e)}")
            
            # 암호화 설정 확인
            try:
                encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                bucket_data['encryption'] = True
            except Exception as e:
                # 암호화 설정이 없는 경우 예외 발생, 무시
                bucket_data['encryption'] = False
            
            # 라이프사이클 규칙 확인
            try:
                lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                bucket_data['lifecycle_rules'] = lifecycle.get('Rules', [])
            except Exception as e:
                # 라이프사이클 설정이 없는 경우 예외 발생, 무시
                pass
            
            # 태그 확인
            try:
                tags = s3_client.get_bucket_tagging(Bucket=bucket_name)
                bucket_data['tags'] = {tag['Key']: tag['Value'] for tag in tags.get('TagSet', [])}
            except Exception as e:
                # 태그가 없는 경우 예외 발생, 무시
                pass
            
            # 버킷 크기 및 객체 수 확인 (CloudWatch 메트릭 사용)
            try:
                cloudwatch = boto3.client(
                    'cloudwatch',
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key,
                    region_name=region
                )
                
                # 버킷 크기 메트릭
                size_response = cloudwatch.get_metric_statistics(
                    Namespace='AWS/S3',
                    MetricName='BucketSizeBytes',
                    Dimensions=[
                        {'Name': 'BucketName', 'Value': bucket_name},
                        {'Name': 'StorageType', 'Value': 'StandardStorage'}
                    ],
                    StartTime=bucket['CreationDate'],
                    EndTime=bucket['CreationDate'],
                    Period=86400,
                    Statistics=['Average']
                )
                
                if size_response['Datapoints']:
                    bucket_data['size'] = size_response['Datapoints'][0]['Average']
                
                # 객체 수 메트릭
                count_response = cloudwatch.get_metric_statistics(
                    Namespace='AWS/S3',
                    MetricName='NumberOfObjects',
                    Dimensions=[
                        {'Name': 'BucketName', 'Value': bucket_name},
                        {'Name': 'StorageType', 'Value': 'AllStorageTypes'}
                    ],
                    StartTime=bucket['CreationDate'],
                    EndTime=bucket['CreationDate'],
                    Period=86400,
                    Statistics=['Average']
                )
                
                if count_response['Datapoints']:
                    bucket_data['object_count'] = count_response['Datapoints'][0]['Average']
            except Exception as e:
                logger.error(f"Error getting metrics for {bucket_name}: {str(e)}")
            
            buckets.append(bucket_data)
            logger.info(f"Successfully collected data for bucket {bucket_name}")
        
        result = {'buckets': buckets}
        logger.info(f"Successfully collected data for {len(buckets)} buckets")
        return result
    except Exception as e:
        logger.error(f"Error in get_s3_data: {str(e)}")
        return {'error': str(e)}