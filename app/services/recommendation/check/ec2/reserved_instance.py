# app/services/ec2_checks/reserved_instance.py
# Check for reserved instance recommendations

import logging
from .utils import calculate_runtime

# 로깅 설정
logger = logging.getLogger(__name__)

def check_reserved_instance_recommendation(instance):
    """예약 인스턴스 추천"""
    try:
        logger.debug(f"Checking reserved instance recommendation for instance {instance.get('id')}")
        if instance['state'] == 'running':
            runtime = calculate_runtime(instance.get('launch_time'))
            if runtime and runtime.days >= 30:
                logger.info(f"Instance {instance['id']} has been running for {runtime.days} days. Recommending reserved instance.")
                return {
                    'service': 'EC2',
                    'resource': instance['id'],
                    'message': f"{runtime.days}일 동안 실행 중인 인스턴스의 예약 인스턴스 전환이 필요합니다.",
                    'severity': '중간',
                    'problem': f"온디맨드 인스턴스가 {runtime.days}일 동안 지속 실행 중입니다.",
                    'impact': "온디맨드 요금으로 인한 추가 비용이 발생하고 있습니다.",
                    'benefit': "예약 인스턴스 적용으로 최대 72%까지 비용 절감이 가능합니다.",
                    'steps': [
                        "인스턴스의 사용 패턴을 분석합니다.",
                        "적절한 예약 기간과 선결제 옵션을 선택합니다.",
                        "예약 인스턴스를 구매합니다."
                    ]
                }
        logger.debug(f"No reserved instance recommendation for instance {instance.get('id')}")
        return None
    except Exception as e:
        logger.error(f"Error in check_reserved_instance_recommendation for instance {instance.get('id')}: {str(e)}", exc_info=True)
        return None