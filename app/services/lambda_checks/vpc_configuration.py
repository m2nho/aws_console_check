from typing import Dict
from app.services.lambda_checks.utils import logger

def check_vpc_configuration(function: Dict) -> Dict:
    """VPC 구성 검사"""
    function_name = function.get('FunctionName', 'unknown')
    vpc_config = function.get('VpcConfig', {})
    logger.debug(f"Checking VPC configuration for function: {function_name}")
    
    try:
        if not vpc_config or not vpc_config.get('VpcId'):
            logger.info(f"Function {function_name} is not configured with VPC")
            return {
                'service': 'Lambda',
                'resource': function_name,
                'message': "Lambda 함수의 VPC 구성을 점검하세요.",
                'severity': '중간',
                'problem': "Lambda 함수가 VPC 없이 실행되고 있습니다.",
                'impact': "보안상 민감한 리소스에 접근이 제한되며, 네트워크 격리가 불완전할 수 있습니다.",
                'benefit': "VPC 구성을 통해 리소스 접근 제어 및 네트워크 보안을 강화할 수 있습니다.",
                'steps': [
                    "함수가 접근해야 하는 리소스를 파악합니다.",
                    "적절한 VPC, 서브넷, 보안 그룹을 선택합니다.",
                    "필요한 경우 VPC 엔드포인트를 구성합니다.",
                    "Lambda 함수에 VPC 구성을 적용합니다."
                ]
            }
        return None
    except Exception as e:
        logger.error(f"Error in check_vpc_configuration for function {function_name}: {str(e)}")
        return None