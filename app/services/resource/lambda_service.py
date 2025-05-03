import boto3
from datetime import datetime, timedelta
from typing import Dict, List, Any
import pytz
import logging

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

def get_lambda_data(aws_access_key: str, aws_secret_key: str, region: str) -> Dict:
    """Lambda 함수 데이터 수집"""
    logger.info("Starting Lambda data collection")
    try:
        lambda_client = boto3.client(
            'lambda',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        cloudwatch = boto3.client(
            'cloudwatch',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )

        response = lambda_client.list_functions()
        functions = []
        
        logger.info(f"Found {len(response.get('Functions', []))} Lambda functions")
        
        for function in response.get('Functions', []):
            logger.debug(f"Processing function {function['FunctionName']}")
            
            # 기본 함수 정보
            function_data = {
                'FunctionName': function['FunctionName'],
                'FunctionArn': function['FunctionArn'],
                'Runtime': function['Runtime'],
                'MemorySize': function['MemorySize'],
                'Timeout': function['Timeout'],
                'CodeSize': function['CodeSize'],
                'LastModified': function['LastModified'],
                'Handler': function['Handler'],
                'Environment': function.get('Environment', {}).get('Variables', {}),
                'TracingConfig': function.get('TracingConfig', {}).get('Mode', 'PassThrough'),
                'Architectures': function.get('Architectures', ['x86_64']),
                'Tags': {},
                'ReservedConcurrency': None,
                'DeadLetterConfig': function.get('DeadLetterConfig', {}),
                'Layers': function.get('Layers', []),
                'VersionsInfo': [],
                'UrlConfig': None,
                'VpcConfig': function.get('VpcConfig', {})
            }
            
            # 태그 정보 수집
            logger.debug(f"Collecting tags for {function['FunctionName']}")
            try:
                tags_response = lambda_client.list_tags(Resource=function['FunctionArn'])
                function_data['Tags'] = tags_response.get('Tags', {})
            except Exception as e:
                logger.error(f"Error collecting tags: {str(e)}")
            
            # 예약된 동시성 정보 수집
            logger.debug(f"Collecting concurrency info for {function['FunctionName']}")
            try:
                concurrency = lambda_client.get_function_concurrency(
                    FunctionName=function['FunctionName']
                )
                function_data['ReservedConcurrency'] = concurrency.get('ReservedConcurrentExecutions')
            except Exception as e:
                logger.error(f"Error collecting concurrency info: {str(e)}")
            
            # 함수 URL 구성 정보 수집
            logger.debug(f"Collecting URL config for {function['FunctionName']}")
            try:
                url_config = lambda_client.get_function_url_config(
                    FunctionName=function['FunctionName']
                )
                function_data['UrlConfig'] = {
                    'AuthType': url_config.get('AuthType'),
                    'Url': url_config.get('FunctionUrl')
                }
            except Exception as e:
                # URL이 구성되지 않은 경우 예외 발생, 무시
                pass
            
            # 버전 정보 수집
            logger.debug(f"Collecting versions for {function['FunctionName']}")
            try:
                versions = lambda_client.list_versions_by_function(
                    FunctionName=function['FunctionName']
                )
                function_data['VersionsInfo'] = [
                    {'Version': v.get('Version')} for v in versions.get('Versions', [])
                ]
            except Exception as e:
                logger.error(f"Error collecting versions: {str(e)}")
            
            # 로그 출력 검사
            logger.debug(f"Checking debug logs for {function['FunctionName']}")
            function_data['DebugLogsDetected'] = _check_debug_logs(
                aws_access_key, aws_secret_key, region, function['FunctionName']
            )
            
            functions.append(function_data)
            logger.info(f"Successfully collected data for function {function['FunctionName']}")
        
        result = {'functions': functions}
        logger.info(f"Successfully collected data for {len(functions)} functions")
        return result
    except Exception as e:
        logger.error(f"Error in get_lambda_data: {str(e)}")
        return {'error': str(e)}

def _check_debug_logs(aws_access_key: str, aws_secret_key: str, region: str, function_name: str) -> bool:
    """디버깅 로그 출력 검사"""
    try:
        logs_client = boto3.client(
            'logs',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        # 로그 그룹 이름 형식
        log_group_name = f"/aws/lambda/{function_name}"
        
        # 로그 그룹 존재 여부 확인
        log_groups = logs_client.describe_log_groups(
            logGroupNamePrefix=log_group_name,
            limit=1
        )
        
        # 로그 그룹이 존재하지 않으면 디버깅 로그가 없다고 판단
        if not log_groups.get('logGroups'):
            logger.info(f"Log group {log_group_name} does not exist for function {function_name}")
            return False
            
        # 최근 로그 이벤트 검색
        response = logs_client.filter_log_events(
            logGroupName=log_group_name,
            limit=100
        )
        
        # 디버깅 로그 패턴 검색
        debug_patterns = ['console.log(', 'print(', 'logger.debug(', 'System.out.println(']
        for event in response.get('events', []):
            message = event.get('message', '')
            for pattern in debug_patterns:
                if pattern in message:
                    return True
        
        return False
    except Exception as e:
        logger.error(f"Error checking debug logs: {str(e)}")
        return False