from typing import Dict
from app.services.recommendation.check.lambda_service.utils import logger

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