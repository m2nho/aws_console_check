# app/services/ec2_checks/tag_recommendations.py
# Check for tag recommendations

import logging

# 로깅 설정
logger = logging.getLogger(__name__)

def check_tag_recommendations(instance):
    """태그 관리 검사"""
    try:
        logger.debug(f"Checking tag recommendations for instance {instance.get('id')}")
        required_tags = {'Name', 'Environment', 'Owner', 'Project'}
        instance_tags = {tag['Key'] for tag in instance.get('tags', [])}
        missing_tags = required_tags - instance_tags

        if missing_tags:
            logger.warning(f"Instance {instance['id']} is missing required tags: {missing_tags}")
            return {
                'service': 'EC2',
                'resource': instance['id'],
                'message': f"필수 태그 보완이 필요합니다.",
                'severity': '낮음',
                'problem': f"다음 필수 태그가 누락되어 있습니다: {', '.join(missing_tags)}",
                'impact': "리소스 관리 및 비용 추적이 어려운 상태입니다.",
                'benefit': "체계적인 리소스 관리 및 비용 추적이 가능합니다.",
                'steps': [
                    "필수 태그를 정의하고 적용합니다.",
                    "태그 기반 비용 할당을 설정합니다.",
                    "자동 태깅 규칙을 구성합니다.",
                    "정기적인 태그 컴플라이언스를 검토합니다."
                ]
            }
        logger.debug(f"No missing tags found for instance {instance['id']}")
        return None
    except Exception as e:
        logger.error(f"Error in check_tag_recommendations for instance {instance.get('id')}: {str(e)}", exc_info=True)
        return None