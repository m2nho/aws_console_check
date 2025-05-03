from typing import Dict
from app.services.recommendation.check.lambda_service.utils import logger

def check_public_layers(function: Dict) -> Dict:
    """퍼블릭 Layer 사용 검사"""
    function_name = function.get('FunctionName', 'unknown')
    layers = function.get('Layers', [])
    logger.debug(f"Checking public layers for function: {function_name}")
    
    try:
        # 실제로는 Layer ARN을 분석하여 외부 계정 소유인지 확인해야 함
        # 여기서는 간단히 처리
        has_public_layers = False
        
        if layers:
            # 예시: 외부 계정 소유 Layer 여부 확인 로직
            for layer in layers:
                layer_arn = layer.get('Arn', '')
                if 'arn:aws:lambda' in layer_arn and not layer_arn.startswith('arn:aws:lambda:region:account-id:'):
                    has_public_layers = True
                    break
        
        if has_public_layers:
            logger.warning(f"Function {function_name} is using public layers")
            return {
                'service': 'Lambda',
                'resource': function_name,
                'message': "Lambda 함수에서 사용 중인 Layer를 검토하세요.",
                'severity': '중간',
                'problem': "외부 퍼블릭 Layer 사용 시 악성 코드나 알려지지 않은 코드가 포함되어 있을 수 있습니다.",
                'impact': "보안 취약점 또는 예기치 않은 동작의 위험이 있습니다.",
                'benefit': "신뢰할 수 있는 내부 Layer 또는 검증된 Layer를 사용함으로써 보안성을 확보할 수 있습니다.",
                'steps': [
                    "Lambda Layer ARN이 조직 내부 소유인지 확인합니다.",
                    "외부 소유 Layer의 코드를 검토하거나 사용을 중단합니다.",
                    "필요한 경우 자체 Layer를 빌드하여 배포합니다."
                ]
            }
        return None
    except Exception as e:
        logger.error(f"Error in check_public_layers for function {function_name}: {str(e)}")
        return None