from typing import Dict
from app.services.recommendation.check.lambda_service.utils import logger

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