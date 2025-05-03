from typing import Dict
from app.services.recommendation.check.lambda_service.utils import logger

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