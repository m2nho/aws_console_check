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
def check_memory_size(function: Dict) -> Dict:
    """메모리 설정 검사"""
    function_name = function.get('FunctionName', 'unknown')
    memory_size = function.get('MemorySize', 0)
    logger.debug(f"Checking memory size for function: {function_name}")
    
    try:
        if memory_size > 512:
            logger.info(f"Function {function_name} has high memory setting: {memory_size}MB")
            return {
                'service': 'Lambda',
                'resource': function_name,
                'message': "Lambda 함수의 메모리 설정을 점검하세요.",
                'severity': '낮음',
                'problem': f"Lambda 함수의 메모리가 {memory_size}MB로 설정되어 있습니다.",
                'impact': "필요 이상의 메모리 할당으로 인해 불필요한 비용이 발생할 수 있습니다.",
                'benefit': "적절한 메모리 설정을 통해 비용을 절감할 수 있습니다.",
                'steps': [
                    "CloudWatch Logs에서 실제 메모리 사용량을 확인합니다.",
                    "AWS Lambda 콘솔에서 함수 구성을 편집합니다.",
                    "메모리 할당을 실제 사용량에 맞게 조정합니다.",
                    "변경 후 함수 성능을 모니터링합니다."
                ]
            }
        return None
    except Exception as e:
        logger.error(f"Error in check_memory_size for function {function_name}: {str(e)}")
        return None

def check_timeout_setting(function: Dict) -> Dict:
    """타임아웃 설정 검사"""
    function_name = function.get('FunctionName', 'unknown')
    timeout = function.get('Timeout', 0)
    logger.debug(f"Checking timeout setting for function: {function_name}")
    
    try:
        if timeout > 60:
            logger.info(f"Function {function_name} has high timeout setting: {timeout} seconds")
            return {
                'service': 'Lambda',
                'resource': function_name,
                'message': "Lambda 함수의 타임아웃 설정을 점검하세요.",
                'severity': '중간',
                'problem': f"Lambda 함수의 타임아웃이 {timeout}초로 설정되어 있습니다.",
                'impact': "장시간 실행되는 작업은 Lambda에 적합하지 않아 비용 효율성이 떨어질 수 있습니다.",
                'benefit': "적절한 실행 시간 분리로 효율적인 자원 사용이 가능합니다.",
                'steps': [
                    "CloudWatch Logs에서 실행 시간을 분석합니다.",
                    "실행 시간이 길다면 작업을 더 작은 단위로 분할합니다.",
                    "Step Functions나 ECS, AWS Batch로의 마이그레이션을 검토합니다."
                ]
            }
        return None
    except Exception as e:
        logger.error(f"Error in check_timeout_setting for function {function_name}: {str(e)}")
        return None

def check_runtime_version(function: Dict) -> Dict:
    """런타임 버전 검사"""
    function_name = function.get('FunctionName', 'unknown')
    runtime = function.get('Runtime', '')
    logger.debug(f"Checking runtime version for function: {function_name}")
    
    try:
        outdated_runtimes = [
            'nodejs10.x', 'nodejs12.x', 'nodejs14.x',
            'python3.6', 'python3.7',
            'ruby2.5', 'ruby2.7',
            'java8', 'java8.al2',
            'dotnetcore2.1', 'dotnetcore3.1',
            'go1.x'
        ]
        
        if runtime in outdated_runtimes:
            logger.warning(f"Function {function_name} uses outdated runtime: {runtime}")
            return {
                'service': 'Lambda',
                'resource': function_name,
                'message': "Lambda 함수의 런타임 버전을 점검하세요.",
                'severity': '높음',
                'problem': "지원 종료되거나 곧 종료될 런타임을 사용하고 있습니다.",
                'impact': "보안 업데이트가 제공되지 않아 보안 취약점에 노출될 수 있습니다.",
                'benefit': "최신 런타임으로의 업그레이드를 통해 보안성과 안정성을 확보할 수 있습니다.",
                'steps': [
                    "함수 코드의 호환성을 검토합니다.",
                    "새 런타임에서 테스트를 진행합니다.",
                    "필요한 코드 수정을 수행하고 배포합니다.",
                    "배포 후 성능과 안정성을 모니터링합니다."
                ]
            }
        return None
    except Exception as e:
        logger.error(f"Error in check_runtime_version for function {function_name}: {str(e)}")
        return None

def check_code_size(function: Dict) -> Dict:
    """코드 크기 검사"""
    function_name = function.get('FunctionName', 'unknown')
    code_size = function.get('CodeSize', 0)
    code_size_mb = code_size / 1024 / 1024  # Convert to MB
    logger.debug(f"Checking code size for function: {function_name}")
    
    try:
        if code_size > 5 * 1024 * 1024:  # 5MB
            logger.warning(f"Function {function_name} has large code size: {code_size_mb:.2f}MB")
            return {
                'service': 'Lambda',
                'resource': function_name,
                'message': "Lambda 함수의 코드 크기를 점검하세요.",
                'severity': '중간',
                'problem': f"Lambda 함수의 코드 크기가 5MB를 초과합니다.",
                'impact': "콜드 스타트 지연 및 배포 시간이 증가할 수 있습니다.",
                'benefit': "코드 최적화를 통해 함수 응답 시간 및 배포 속도를 개선할 수 있습니다.",
                'steps': [
                    "불필요한 의존성과 파일을 제거합니다.",
                    "공통 라이브러리는 Lambda Layer로 분리합니다.",
                    "코드 최적화를 통해 크기를 줄입니다.",
                    "필요 시 기능 단위로 함수 분할을 검토합니다."
                ]
            }
        return None
    except Exception as e:
        logger.error(f"Error in check_code_size for function {function_name}: {str(e)}")
        return None

def check_xray_tracing(function: Dict) -> Dict:
    """X-Ray 추적 검사"""
    function_name = function.get('FunctionName', 'unknown')
    tracing_config = function.get('TracingConfig', 'PassThrough')
    logger.debug(f"Checking X-Ray tracing for function: {function_name}")
    
    try:
        if tracing_config == 'PassThrough':
            logger.info(f"Function {function_name} has X-Ray tracing disabled")
            return {
                'service': 'Lambda',
                'resource': function_name,
                'message': "X-Ray 추적 설정을 점검하세요.",
                'severity': '낮음',
                'problem': "X-Ray 추적이 비활성화되어 있습니다.",
                'impact': "함수 성능이나 오류 원인을 분석하기 어렵습니다.",
                'benefit': "X-Ray 추적을 통해 성능 병목 및 문제점을 빠르게 식별할 수 있습니다.",
                'steps': [
                    "Lambda 콘솔에서 함수 구성을 편집합니다.",
                    "모니터링 설정에서 X-Ray를 활성화합니다.",
                    "필요한 IAM 권한을 부여합니다.",
                    "X-Ray 콘솔에서 추적 결과를 확인합니다."
                ]
            }
        return None
    except Exception as e:
        logger.error(f"Error in check_xray_tracing for function {function_name}: {str(e)}")
        return None

def check_vpc_configuration(function: Dict) -> Dict:
    """VPC 구성 검사"""
    function_name = function.get('FunctionName', 'unknown')
    vpc_config = function.get('VpcConfig', {})
    logger.debug(f"Checking VPC configuration for function: {function_name}")
    
    try:
        if not vpc_config or not vpc_config.get('VpcId'):
            logger.info(f"Function {function_name} is not configured with VPC")
            return {
                'service': 'Lambda',
                'resource': function_name,
                'message': "Lambda 함수의 VPC 구성을 점검하세요.",
                'severity': '중간',
                'problem': "Lambda 함수가 VPC 없이 실행되고 있습니다.",
                'impact': "보안상 민감한 리소스에 접근이 제한되며, 네트워크 격리가 불완전할 수 있습니다.",
                'benefit': "VPC 구성을 통해 리소스 접근 제어 및 네트워크 보안을 강화할 수 있습니다.",
                'steps': [
                    "함수가 접근해야 하는 리소스를 파악합니다.",
                    "적절한 VPC, 서브넷, 보안 그룹을 선택합니다.",
                    "필요한 경우 VPC 엔드포인트를 구성합니다.",
                    "Lambda 함수에 VPC 구성을 적용합니다."
                ]
            }
        return None
    except Exception as e:
        logger.error(f"Error in check_vpc_configuration for function {function_name}: {str(e)}")
        return None

def check_arm64_architecture(function: Dict) -> Dict:
    """ARM64 아키텍처 마이그레이션 검사"""
    function_name = function.get('FunctionName', 'unknown')
    architectures = function.get('Architectures', ['x86_64'])
    logger.debug(f"Checking ARM64 architecture for function: {function_name}")
    
    try:
        if 'arm64' not in architectures:
            logger.info(f"Function {function_name} is not using ARM64 architecture")
            return {
                'service': 'Lambda',
                'resource': function_name,
                'message': "Lambda 함수의 아키텍처를 점검하세요.",
                'severity': '낮음',
                'problem': "x86_64 아키텍처에서 실행되고 있습니다.",
                'impact': "ARM64 아키텍처 대비 비용 효율성이 낮습니다.",
                'benefit': "ARM64 사용 시 비용 절감 및 성능 개선이 가능합니다.",
                'steps': [
                    "ARM64 아키텍처와의 코드 호환성을 검토합니다.",
                    "테스트 환경에서 ARM64 아키텍처로 실행해 봅니다.",
                    "종속성 라이브러리를 ARM64에 맞게 준비합니다.",
                    "프로덕션 환경으로 점진적 마이그레이션을 진행합니다."
                ]
            }
        return None
    except Exception as e:
        logger.error(f"Error in check_arm64_architecture for function {function_name}: {str(e)}")
        return None

def check_environment_encryption(function: Dict) -> Dict:
    """환경 변수 암호화 검사"""
    function_name = function.get('FunctionName', 'unknown')
    environment = function.get('Environment', {})
    logger.debug(f"Checking environment encryption for function: {function_name}")
    
    try:
        # 실제로는 KMS 키 사용 여부를 확인해야 하지만, 예시에서는 간단히 처리
        # 실제 구현에서는 KMS 키 ARN이 있는지 확인하는 로직이 필요
        is_encrypted = False  # 기본적으로 암호화되지 않았다고 가정
        
        if not is_encrypted and environment:
            logger.warning(f"Function {function_name} has unencrypted environment variables")
            return {
                'service': 'Lambda',
                'resource': function_name,
                'message': "Lambda 함수의 환경 변수 암호화 설정을 점검하세요.",
                'severity': '높음',
                'problem': "환경 변수가 추가 암호화 없이 저장되어 있습니다.",
                'impact': "환경 변수에 포함된 민감한 정보가 노출될 위험이 있습니다.",
                'benefit': "KMS 암호화를 통해 민감 정보 보호 수준을 향상시킬 수 있습니다.",
                'steps': [
                    "KMS 키를 생성하거나 기존 키를 선택합니다.",
                    "Lambda 함수의 환경 변수에 암호화를 적용합니다.",
                    "필요한 IAM 권한을 구성합니다.",
                    "암호화된 변수 사용 여부를 테스트합니다."
                ]
            }
        return None
    except Exception as e:
        logger.error(f"Error in check_environment_encryption for function {function_name}: {str(e)}")
        return None

def check_tag_management(function: Dict) -> Dict:
    """태그 관리 검사"""
    function_name = function.get('FunctionName', 'unknown')
    tags = function.get('Tags', {})
    logger.debug(f"Checking tag management for function: {function_name}")
    
    try:
        if not tags:
            logger.info(f"Function {function_name} has no tags")
            return {
                'service': 'Lambda',
                'resource': function_name,
                'message': "Lambda 함수의 태그 설정을 점검하세요.",
                'severity': '낮음',
                'problem': "Lambda 함수에 태그가 설정되어 있지 않습니다.",
                'impact': "리소스 관리, 비용 분석 및 접근 제어에 어려움이 있습니다.",
                'benefit': "태그를 통해 리소스를 논리적으로 구분하고 효율적인 관리가 가능합니다.",
                'steps': [
                    "조직에 맞는 태깅 전략을 수립합니다.",
                    "필수 태그 키와 값을 정의합니다.",
                    "Lambda 콘솔 또는 CLI에서 태그를 추가합니다.",
                    "태그 기반 정책을 활용하여 접근 제어를 설정합니다."
                ]
            }
        return None
    except Exception as e:
        logger.error(f"Error in check_tag_management for function {function_name}: {str(e)}")
        return None

def check_public_url_endpoint(function: Dict) -> Dict:
    """공개된 Lambda URL 엔드포인트 검사"""
    function_name = function.get('FunctionName', 'unknown')
    url_config = function.get('UrlConfig', {})
    logger.debug(f"Checking public URL endpoint for function: {function_name}")
    
    try:
        if url_config and url_config.get('AuthType') == 'NONE':
            logger.warning(f"Function {function_name} has public URL endpoint without authentication")
            return {
                'service': 'Lambda',
                'resource': function_name,
                'message': "Lambda URL의 공개 접근 설정을 점검하세요.",
                'severity': '높음',
                'problem': "Lambda 함수가 인증 없이 누구나 접근 가능한 URL을 통해 호출될 수 있습니다.",
                'impact': "공격자에 의한 오용 또는 무단 접근으로 인해 보안 위협이 발생할 수 있습니다.",
                'benefit': "Lambda URL에 인증을 설정함으로써 외부 접근을 안전하게 제한할 수 있습니다.",
                'steps': [
                    "Lambda URL 구성을 확인합니다.",
                    "인증 유형이 'AWS_IAM'으로 설정되어 있는지 확인합니다.",
                    "IAM 정책을 통해 필요한 사용자에게만 접근 권한을 부여합니다.",
                    "인증되지 않은 공개 접근을 즉시 차단합니다."
                ]
            }
        return None
    except Exception as e:
        logger.error(f"Error in check_public_url_endpoint for function {function_name}: {str(e)}")
        return None

def check_public_layers(function: Dict) -> Dict:
    """퍼블릭 Layer 사용 검사"""
    function_name = function.get('FunctionName', 'unknown')
    layers = function.get('Layers', [])
    logger.debug(f"Checking public layers for function: {function_name}")
    
    try:
        # 실제로는 Layer ARN을 분석하여 외부 계정 소유인지 확인해야 함
        # 여기서는 간단히 처리
        has_public_layers = False
        
        if layers:
            # 예시: 외부 계정 소유 Layer 여부 확인 로직
            for layer in layers:
                layer_arn = layer.get('Arn', '')
                if 'arn:aws:lambda' in layer_arn and not layer_arn.startswith('arn:aws:lambda:region:account-id:'):
                    has_public_layers = True
                    break
        
        if has_public_layers:
            logger.warning(f"Function {function_name} is using public layers")
            return {
                'service': 'Lambda',
                'resource': function_name,
                'message': "Lambda 함수에서 사용 중인 Layer를 검토하세요.",
                'severity': '중간',
                'problem': "외부 퍼블릭 Layer 사용 시 악성 코드나 알려지지 않은 코드가 포함되어 있을 수 있습니다.",
                'impact': "보안 취약점 또는 예기치 않은 동작의 위험이 있습니다.",
                'benefit': "신뢰할 수 있는 내부 Layer 또는 검증된 Layer를 사용함으로써 보안성을 확보할 수 있습니다.",
                'steps': [
                    "Lambda Layer ARN이 조직 내부 소유인지 확인합니다.",
                    "외부 소유 Layer의 코드를 검토하거나 사용을 중단합니다.",
                    "필요한 경우 자체 Layer를 빌드하여 배포합니다."
                ]
            }
        return None
    except Exception as e:
        logger.error(f"Error in check_public_layers for function {function_name}: {str(e)}")
        return None

def check_debug_logs_output(function: Dict) -> Dict:
    """디버깅 로그 출력 검사"""
    function_name = function.get('FunctionName', 'unknown')
    debug_logs_detected = function.get('DebugLogsDetected', False)
    logger.debug(f"Checking debug logs output for function: {function_name}")
    
    try:
        if debug_logs_detected:
            logger.warning(f"Function {function_name} has debug logs output")
            return {
                'service': 'Lambda',
                'resource': function_name,
                'message': "디버깅 로그 출력을 점검하세요.",
                'severity': '낮음',
                'problem': "디버깅용 로그가 과도하게 출력되고 있습니다.",
                'impact': "CloudWatch Logs 비용 증가 및 민감한 정보 노출 가능성이 있습니다.",
                'benefit': "불필요한 로그 제거를 통해 운영 효율성과 보안을 강화할 수 있습니다.",
                'steps': [
                    "함수 코드에서 디버깅 로그를 제거하거나 로그 레벨 제어 로직을 도입합니다.",
                    "민감한 정보가 로그로 출력되지 않도록 확인합니다.",
                    "CloudWatch 로그 그룹의 보관 기간을 설정합니다."
                ]
            }
        return None
    except Exception as e:
        logger.error(f"Error in check_debug_logs_output for function {function_name}: {str(e)}")
        return None

def check_reserved_concurrency(function: Dict) -> Dict:
    """Reserved Concurrency 미설정 검사"""
    function_name = function.get('FunctionName', 'unknown')
    reserved_concurrency = function.get('ReservedConcurrency')
    logger.debug(f"Checking reserved concurrency for function: {function_name}")
    
    try:
        if reserved_concurrency is None:
            logger.info(f"Function {function_name} has no reserved concurrency")
            return {
                'service': 'Lambda',
                'resource': function_name,
                'message': "Lambda 함수의 동시성 제한 설정을 점검하세요.",
                'severity': '중간',
                'problem': "동시성 제한이 없어 과도한 요청이 발생하면 다른 함수나 시스템에 영향을 줄 수 있습니다.",
                'impact': "예상치 못한 트래픽 증가 시 장애로 이어질 수 있습니다.",
                'benefit': "적절한 동시성 제한으로 서비스 안정성을 확보할 수 있습니다.",
                'steps': [
                    "예상되는 최대 트래픽 기반으로 Reserved Concurrency 값을 설정합니다.",
                    "다른 핵심 함수의 리소스를 보호하기 위해 제한을 검토합니다.",
                    "Auto Scaling과 함께 조합 사용을 고려합니다."
                ]
            }
        return None
    except Exception as e:
        logger.error(f"Error in check_reserved_concurrency for function {function_name}: {str(e)}")
        return None

def check_dead_letter_queue(function: Dict) -> Dict:
    """Dead Letter Queue (DLQ) 미설정 검사"""
    function_name = function.get('FunctionName', 'unknown')
    dlq_config = function.get('DeadLetterConfig', {})
    logger.debug(f"Checking dead letter queue for function: {function_name}")
    
    try:
        if not dlq_config:
            logger.info(f"Function {function_name} has no dead letter queue configured")
            return {
                'service': 'Lambda',
                'resource': function_name,
                'message': "Lambda 함수의 실패 처리 구성을 점검하세요.",
                'severity': '중간',
                'problem': "비동기 함수 실패 시 실패 이벤트가 손실될 수 있습니다.",
                'impact': "실패 원인 추적이나 후속 처리가 어려워집니다.",
                'benefit': "DLQ를 통해 실패 이벤트를 저장하고 안정적인 후속 조치가 가능합니다.",
                'steps': [
                    "SQS 또는 SNS를 DLQ로 설정합니다.",
                    "IAM 역할에 DLQ 관련 권한을 부여합니다.",
                    "실패 이벤트 처리 및 알림 워크플로우를 구성합니다."
                ]
            }
        return None
    except Exception as e:
        logger.error(f"Error in check_dead_letter_queue for function {function_name}: {str(e)}")
        return None

def check_version_alias_usage(function: Dict) -> Dict:
    """최신 버전 alias 미사용 검사"""
    function_name = function.get('FunctionName', 'unknown')
    versions_info = function.get('VersionsInfo', [])
    logger.debug(f"Checking version alias usage for function: {function_name}")
    
    try:
        # 버전 정보가 있지만 $LATEST만 사용하는 경우 확인
        # 실제로는 alias 정보도 확인해야 하지만, 예시에서는 간단히 처리
        has_published_versions = False
        for version in versions_info:
            if version.get('Version') != '$LATEST':
                has_published_versions = True
                break
        
        if versions_info and not has_published_versions:
            logger.warning(f"Function {function_name} is only using $LATEST version")
            return {
                'service': 'Lambda',
                'resource': function_name,
                'message': "Lambda 함수 버전 관리 및 alias 사용을 점검하세요.",
                'severity': '낮음',
                'problem': "$LATEST만을 사용하는 경우 변경 추적 및 롤백이 어렵습니다.",
                'impact': "운영 환경에서 예기치 않게 함수가 바뀌는 위험이 있습니다.",
                'benefit': "고정된 버전과 alias 사용을 통해 배포 관리 및 안정성을 강화할 수 있습니다.",
                'steps': [
                    "코드 배포 후 Lambda 버전을 고정하여 게시합니다.",
                    "alias를 생성하여 고정된 버전과 연결합니다.",
                    "배포 자동화를 위한 alias 전환 전략을 구성합니다."
                ]
            }
        return None
    except Exception as e:
        logger.error(f"Error in check_version_alias_usage for function {function_name}: {str(e)}")
        return None

