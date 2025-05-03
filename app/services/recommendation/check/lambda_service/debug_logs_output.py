from typing import Dict
from app.services.recommendation.check.lambda_service.utils import logger

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