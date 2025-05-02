import boto3
from datetime import datetime, timedelta
from typing import Dict, List, Any
import pytz
import logging

# Import check functions from individual files
from app.services.lambda_checks import (
    check_memory_size,
    check_timeout_setting,
    check_runtime_version,
    check_code_size,
    check_xray_tracing,
    check_vpc_configuration,
    check_arm64_architecture,
    check_environment_encryption,
    check_tag_management,
    check_public_url_endpoint,
    check_public_layers,
    check_debug_logs_output,
    check_reserved_concurrency,
    check_dead_letter_queue,
    check_version_alias_usage
)

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

def get_lambda_recommendations(functions: Dict) -> List[Dict]:
    """Lambda 함수 추천 사항 수집"""
    logger.info("Starting Lambda recommendations analysis")
    try:
        recommendations = []

        if not functions:
            logger.warning("No functions data found")
            return []

        # functions가 리스트인 경우
        if isinstance(functions, list):
            function_list = functions
        # functions가 딕셔너리이고 'functions' 키가 있는 경우
        elif isinstance(functions, dict) and 'functions' in functions:
            function_list = functions['functions']
        # functions가 딕셔너리이지만 'functions' 키가 없는 경우
        elif isinstance(functions, dict):
            function_list = [functions]
        else:
            logger.error(f"Unexpected data type: {type(functions)}")
            return []

        logger.info(f"Processing {len(function_list)} functions")

        for function in function_list:
            function_name = function.get('FunctionName', 'unknown')
            logger.debug(f"Processing function: {function_name}")

            try:
                # 1. 메모리 설정 검사
                if function.get('MemorySize', 0) > 512:
                    memory_rec = check_memory_size(function)
                    if memory_rec:
                        recommendations.append(memory_rec)

                # 2. 타임아웃 설정 검사
                if function.get('Timeout', 0) > 60:
                    timeout_rec = check_timeout_setting(function)
                    if timeout_rec:
                        recommendations.append(timeout_rec)

                # 3. 런타임 버전 검사
                if function.get('Runtime'):
                    runtime_rec = check_runtime_version(function)
                    if runtime_rec:
                        recommendations.append(runtime_rec)

                # 4. 코드 크기 검사
                if function.get('CodeSize', 0) > 5 * 1024 * 1024:  # 5MB
                    code_size_rec = check_code_size(function)
                    if code_size_rec:
                        recommendations.append(code_size_rec)

                # 5. X-Ray 추적 검사
                if function.get('TracingConfig') == 'PassThrough':
                    xray_rec = check_xray_tracing(function)
                    if xray_rec:
                        recommendations.append(xray_rec)

                # 6. VPC 구성 검사
                vpc_config = function.get('VpcConfig', {})
                if not vpc_config or not vpc_config.get('VpcId'):
                    vpc_rec = check_vpc_configuration(function)
                    if vpc_rec:
                        recommendations.append(vpc_rec)

                # 7. 환경 변수 암호화 검사
                if function.get('Environment'):
                    env_rec = check_environment_encryption(function)
                    if env_rec:
                        recommendations.append(env_rec)

                # 8. ARM64 아키텍처 마이그레이션 검사
                if 'arm64' not in function.get('Architectures', []):
                    arm64_rec = check_arm64_architecture(function)
                    if arm64_rec:
                        recommendations.append(arm64_rec)

                # 9. 태그 관리 검사
                if not function.get('Tags'):
                    tag_rec = check_tag_management(function)
                    if tag_rec:
                        recommendations.append(tag_rec)

                # 10. 공개된 Lambda URL 엔드포인트 검사
                if function.get('UrlConfig') and function.get('UrlConfig', {}).get('AuthType') == 'NONE':
                    url_rec = check_public_url_endpoint(function)
                    if url_rec:
                        recommendations.append(url_rec)

                # 11. 퍼블릭 Layer 사용 검사
                if function.get('Layers'):
                    layer_rec = check_public_layers(function)
                    if layer_rec:
                        recommendations.append(layer_rec)

                # 12. 디버깅 로그 출력 검사
                if function.get('DebugLogsDetected'):
                    debug_rec = check_debug_logs_output(function)
                    if debug_rec:
                        recommendations.append(debug_rec)

                # 13. Reserved Concurrency 미설정 검사
                if function.get('ReservedConcurrency') is None:
                    concurrency_rec = check_reserved_concurrency(function)
                    if concurrency_rec:
                        recommendations.append(concurrency_rec)

                # 14. Dead Letter Queue (DLQ) 미설정 검사
                if not function.get('DeadLetterConfig'):
                    dlq_rec = check_dead_letter_queue(function)
                    if dlq_rec:
                        recommendations.append(dlq_rec)

                # 15. 최신 버전 alias 미사용 검사
                if function.get('VersionsInfo'):
                    version_rec = check_version_alias_usage(function)
                    if version_rec:
                        recommendations.append(version_rec)

            except Exception as e:
                logger.error(f"Error processing function {function_name}: {str(e)}")
                continue

        logger.info(f"Found {len(recommendations)} recommendations")
        return recommendations
    except Exception as e:
        logger.error(f"Error in get_lambda_recommendations: {str(e)}")
        return []