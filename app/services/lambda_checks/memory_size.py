from typing import Dict
from app.services.lambda_checks.utils import logger

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