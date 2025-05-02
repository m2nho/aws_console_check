from typing import Dict
from app.services.lambda_checks.utils import logger

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