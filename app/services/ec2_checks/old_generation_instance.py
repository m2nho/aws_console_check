# app/services/ec2_checks/old_generation_instance.py
# Check for old generation EC2 instance types

import logging
from .utils import get_new_generation_equivalent

# 로깅 설정
logger = logging.getLogger(__name__)

def check_old_generation_instance(instance):
    """이전 세대 인스턴스 타입 검사"""
    instance_id = instance.get('id', 'unknown')
    instance_type = instance.get('type', '')
    logger.debug(f"Checking instance type for {instance_id}: {instance_type}")
    
    try:
        if instance_type.startswith(('t2.', 'm4.', 'c4.', 'r4.')):
            new_generation = get_new_generation_equivalent(instance_type)
            logger.info(f"Found old generation instance: {instance_id} ({instance_type})")
            return {
                'service': 'EC2',
                'resource': instance_id,
                'message': f"이전 세대 인스턴스 타입({instance_type})의 업그레이드가 필요합니다.",
                'severity': '낮음',
                'problem': f"이전 세대 인스턴스 타입({instance_type})을 사용하고 있습니다.",
                'impact': f"최신 세대 인스턴스({new_generation}) 대비 성능 및 비용 효율성이 낮은 상태입니다.",
                'benefit': "최신 세대 인스턴스 사용으로 성능 향상 및 비용 효율성 개선이 가능합니다.",
                'steps': [
                    "워크로드 패턴을 분석합니다.",
                    f"인스턴스 타입을 {new_generation}으로 변경합니다.",
                    "변경 후 워크로드를 모니터링합니다."
                ]
            }
        return None
    except Exception as e:
        logger.error(f"Error in check_old_generation_instance for {instance_id}: {str(e)}")
        return None