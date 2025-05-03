from typing import Dict
from app.services.recommendation.check.lambda_service.utils import logger

def check_version_alias_usage(function: Dict) -> Dict:
    """최신 버전 alias 미사용 검사"""
    function_name = function.get('FunctionName', 'unknown')
    versions_info = function.get('VersionsInfo', [])
    logger.debug(f"Checking version alias usage for function: {function_name}")
    
    try:
        # 버전 정보가 있지만 $LATEST만 사용하는 경우 확인
        # 실제로는 alias 정보도 확인해야 하지만, 예시에서는 간단히 처리
        has_published_versions = False
        for version in versions_info:
            if version.get('Version') != '$LATEST':
                has_published_versions = True
                break
        
        if versions_info and not has_published_versions:
            logger.warning(f"Function {function_name} is only using $LATEST version")
            return {
                'service': 'Lambda',
                'resource': function_name,
                'message': "Lambda 함수 버전 관리 및 alias 사용을 점검하세요.",
                'severity': '낮음',
                'problem': "$LATEST만을 사용하는 경우 변경 추적 및 롤백이 어렵습니다.",
                'impact': "운영 환경에서 예기치 않게 함수가 바뀌는 위험이 있습니다.",
                'benefit': "고정된 버전과 alias 사용을 통해 배포 관리 및 안정성을 강화할 수 있습니다.",
                'steps': [
                    "코드 배포 후 Lambda 버전을 고정하여 게시합니다.",
                    "alias를 생성하여 고정된 버전과 연결합니다.",
                    "배포 자동화를 위한 alias 전환 전략을 구성합니다."
                ]
            }
        return None
    except Exception as e:
        logger.error(f"Error in check_version_alias_usage for function {function_name}: {str(e)}")
        return None