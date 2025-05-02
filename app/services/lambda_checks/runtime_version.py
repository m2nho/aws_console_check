from typing import Dict
from app.services.lambda_checks.utils import logger

def check_runtime_version(function: Dict) -> Dict:
    """런타임 버전 검사"""
    function_name = function.get('FunctionName', 'unknown')
    runtime = function.get('Runtime', '')
    logger.debug(f"Checking runtime version for function: {function_name}")
    
    try:
        outdated_runtimes = [
            'nodejs10.x', 'nodejs12.x', 'nodejs14.x',
            'python3.6', 'python3.7',
            'ruby2.5', 'ruby2.7',
            'java8', 'java8.al2',
            'dotnetcore2.1', 'dotnetcore3.1',
            'go1.x'
        ]
        
        if runtime in outdated_runtimes:
            logger.warning(f"Function {function_name} uses outdated runtime: {runtime}")
            return {
                'service': 'Lambda',
                'resource': function_name,
                'message': "Lambda 함수의 런타임 버전을 점검하세요.",
                'severity': '높음',
                'problem': "지원 종료되거나 곧 종료될 런타임을 사용하고 있습니다.",
                'impact': "보안 업데이트가 제공되지 않아 보안 취약점에 노출될 수 있습니다.",
                'benefit': "최신 런타임으로의 업그레이드를 통해 보안성과 안정성을 확보할 수 있습니다.",
                'steps': [
                    "함수 코드의 호환성을 검토합니다.",
                    "새 런타임에서 테스트를 진행합니다.",
                    "필요한 코드 수정을 수행하고 배포합니다.",
                    "배포 후 성능과 안정성을 모니터링합니다."
                ]
            }
        return None
    except Exception as e:
        logger.error(f"Error in check_runtime_version for function {function_name}: {str(e)}")
        return None