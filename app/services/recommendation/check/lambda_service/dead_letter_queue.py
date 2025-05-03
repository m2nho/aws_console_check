from typing import Dict
from app.services.recommendation.check.lambda_service.utils import logger

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