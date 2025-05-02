from typing import Dict
from app.services.lambda_checks.utils import logger

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