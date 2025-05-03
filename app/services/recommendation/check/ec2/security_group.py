# app/services/ec2_checks/security_group.py
# Check for security group recommendations

import logging

# 로깅 설정
logger = logging.getLogger(__name__)

def check_security_group_recommendations(instance):
    """보안 그룹 검사"""
    try:
        logger.debug(f"Checking security group recommendations for instance {instance.get('id')}")
        security_issues = []
        for sg in instance.get('security_groups', []):
            # 전체 개방된 포트 검사
            logger.debug(f"Analyzing security group {sg.get('group_id')}")
            if '0.0.0.0/0' in sg.get('ip_ranges', []):
                msg = f"보안 그룹 {sg['group_id']}에 전체 개방된 규칙이 있습니다."
                logger.warning(msg)
                security_issues.append(f"보안 그룹 {sg['group_id']}에 전체 개방된 규칙이 있습니다.")
            
            # 위험 포트 검사
            dangerous_ports = {22, 3389, 21, 23, 445}
            for port in sg.get('ports', []):
                if port in dangerous_ports:
                    security_issues.append(f"보안 그룹 {sg['group_id']}에 위험 포트({port})가 개방되어 있습니다.")

        if security_issues:
            logger.info(f"Found {len(security_issues)} security issues for instance {instance['id']}")
            return {
                'service': 'EC2',
                'resource': instance['id'],
                'message': "보안 그룹 구성 개선이 필요합니다.",
                'severity': '높음',
                'problem': "\n".join(security_issues),
                'impact': "무분별한 접근 허용으로 인한 보안 위험이 있습니다.",
                'benefit': "보안 태세 강화 및 잠재적 위험 감소가 가능합니다.",
                'steps': [
                    "전체 개방된 규칙을 필요한 IP 범위로 제한합니다.",
                    "위험 포트에 대한 접근을 제한합니다.",
                    "불필요한 규칙을 제거합니다.",
                    "정기적인 보안 그룹 규칙 검토를 수행합니다."
                ]
            }
        logger.debug(f"No security issues found for instance {instance['id']}")
        return None
    except Exception as e:
        logger.error(f"Error in check_security_group_recommendations for instance {instance.get('id')}: {str(e)}", exc_info=True)
        return None