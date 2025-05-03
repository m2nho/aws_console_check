from typing import Dict, List, Any
import logging

# Import check functions from individual files
from app.services.recommendation.check.lambda_service import (
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