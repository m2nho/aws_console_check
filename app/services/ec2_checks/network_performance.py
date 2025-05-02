# app/services/ec2_checks/network_performance.py
# Check for network performance recommendations

import logging

# 로깅 설정
logger = logging.getLogger(__name__)

def check_network_performance(instance):
    """네트워크 성능 모니터링"""
    try:
        logger.debug(f"Checking network performance for instance {instance.get('id')}")
        network_metrics = instance.get('network_metrics', {})
        issues = []
        
        # 네트워크 사용량 검사
        if network_metrics.get('NetworkIn', 0) > 100000000:  # 100MB/s
            msg = "높은 인바운드 네트워크 사용량"
            logger.warning(f"Instance {instance['id']}: {msg}")
            issues.append(msg)
        if network_metrics.get('NetworkOut', 0) > 100000000:  # 100MB/s
            msg = "높은 아웃바운드 네트워크 사용량"
            logger.warning(f"Instance {instance['id']}: {msg}")
            issues.append(msg)

        if issues:
            logger.info(f"Found {len(issues)} network performance issues for instance {instance['id']}")
            return {
                'service': 'EC2',
                'resource': instance['id'],
                'message': "네트워크 성능 개선이 필요합니다.",
                'severity': '높음',
                'problem': "\n".join(issues),
                'impact': "애플리케이션 성능 저하 및 사용자 경험이 악화되고 있습니다.",
                'benefit': "네트워크 최적화로 성능 및 안정성 개선이 가능합니다.",
                'steps': [
                    "네트워크 성능 메트릭을 분석합니다.",
                    "ENI 설정을 최적화합니다.",
                    "네트워크 ACL 및 라우팅 테이블을 검토합니다.",
                    "향상된 네트워킹 활성화를 검토합니다."
                ]
            }
        logger.debug(f"No network performance issues found for instance {instance['id']}")
        return None
    except Exception as e:
        logger.error(f"Error in check_network_performance for instance {instance.get('id')}: {str(e)}", exc_info=True)
        return None