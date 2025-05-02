from typing import Dict
from app.services.lambda_checks.utils import logger

def check_public_url_endpoint(function: Dict) -> Dict:
    """공개된 Lambda URL 엔드포인트 검사"""
    function_name = function.get('FunctionName', 'unknown')
    url_config = function.get('UrlConfig', {})
    logger.debug(f"Checking public URL endpoint for function: {function_name}")
    
    try:
        if url_config and url_config.get('AuthType') == 'NONE':
            logger.warning(f"Function {function_name} has public URL endpoint without authentication")
            return {
                'service': 'Lambda',
                'resource': function_name,
                'message': "Lambda URL의 공개 접근 설정을 점검하세요.",
                'severity': '높음',
                'problem': "Lambda 함수가 인증 없이 누구나 접근 가능한 URL을 통해 호출될 수 있습니다.",
                'impact': "공격자에 의한 오용 또는 무단 접근으로 인해 보안 위협이 발생할 수 있습니다.",
                'benefit': "Lambda URL에 인증을 설정함으로써 외부 접근을 안전하게 제한할 수 있습니다.",
                'steps': [
                    "Lambda URL 구성을 확인합니다.",
                    "인증 유형이 'AWS_IAM'으로 설정되어 있는지 확인합니다.",
                    "IAM 정책을 통해 필요한 사용자에게만 접근 권한을 부여합니다.",
                    "인증되지 않은 공개 접근을 즉시 차단합니다."
                ]
            }
        return None
    except Exception as e:
        logger.error(f"Error in check_public_url_endpoint for function {function_name}: {str(e)}")
        return None