import logging
from app.services.recommendation.check.ec2.utils import get_new_generation_equivalent

# 로깅 설정
logger = logging.getLogger(__name__)

def check_old_generation_instance(instance):
    """이전 세대 인스턴스 타입 검사"""
    instance_id = instance.get('id', 'unknown')
    instance_type = instance.get('type', '')
    logger.debug(f"Checking instance type for {instance_id}: {instance_type}")
    
    try:
        # 이전 세대 인스턴스 타입 확인
        old_gen_prefixes = ['t2.', 'm4.', 'c4.', 'r4.']
        
        for prefix in old_gen_prefixes:
            if instance_type.startswith(prefix):
                new_type = get_new_generation_equivalent(instance_type)
                logger.info(f"Found old generation instance: {instance_id} ({instance_type})")
                return {
                    'service': 'EC2',
                    'resource': instance_id,
                    'message': f"이전 세대 인스턴스 타입 업그레이드를 검토하세요.",
                    'severity': '중간',
                    'problem': f"EC2 인스턴스가 이전 세대 타입({instance_type})을 사용 중입니다.",
                    'impact': "최신 세대 인스턴스에 비해 성능이 낮고 비용이 높을 수 있습니다.",
                    'benefit': f"최신 세대 인스턴스 타입({new_type})으로 업그레이드하여 성능 향상 및 비용 절감이 가능합니다.",
                    'steps': [
                        "AWS 콘솔에서 EC2 서비스로 이동합니다.",
                        f"인스턴스 {instance_id}를 선택합니다.",
                        "인스턴스를 중지합니다.",
                        f"인스턴스 유형을 {new_type}으로 변경합니다.",
                        "인스턴스를 다시 시작합니다."
                    ]
                }
        return None
    except Exception as e:
        logger.error(f"Error in check_old_generation_instance for {instance_id}: {str(e)}")
        return None