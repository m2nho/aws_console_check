from typing import Dict
from app.services.recommendation.check.lambda_service.utils import logger

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