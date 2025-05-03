from typing import Dict, List, Any
import logging

# Import check functions from ec2_checks package
from app.services.recommendation.check.ec2 import (
    check_stopped_instance,
    check_old_generation_instance,
    check_reserved_instance_recommendation,
    check_security_group_recommendations,
    check_cpu_utilization,
    check_ebs_optimization,
    check_tag_recommendations,
    check_network_performance,
    check_backup_recommendations
)

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ec2_recommendations.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def get_ec2_recommendations(instances: List[Dict]) -> List[Dict]:
    """EC2 인스턴스 추천 사항 수집"""
    logger.info("Starting EC2 recommendations analysis")
    try:
        recommendations = []

        # 데이터 구조 확인 및 로깅
        logger.info(f"Received data type: {type(instances)}")
        logger.debug(f"Instances data: {instances}")
        
        # instances가 이미 리스트 형태로 전달됨
        instance_list = instances
        logger.info(f"Processing {len(instance_list)} instances")

        for instance in instance_list:
            instance_id = instance.get('id', 'unknown')  # InstanceId -> id
            logger.debug(f"Processing instance: {instance_id}")

            try:
                # 1. 장기 중지된 인스턴스 검사
                if instance.get('state') == 'stopped':  # State -> state
                    stopped_instance_rec = check_stopped_instance(instance)
                    if stopped_instance_rec:
                        recommendations.append(stopped_instance_rec)

                # 2. 이전 세대 인스턴스 타입 검사
                if instance.get('type'):  # InstanceType -> type
                    old_gen_rec = check_old_generation_instance(instance)
                    if old_gen_rec:
                        recommendations.append(old_gen_rec)

                # 3. 예약 인스턴스 추천
                if instance.get('state') == 'running':  # State -> state
                    ri_rec = check_reserved_instance_recommendation(instance)
                    if ri_rec:
                        recommendations.append(ri_rec)

                # 4. 보안 그룹 검사
                if instance.get('security_groups'):  # SecurityGroups -> security_groups
                    security_rec = check_security_group_recommendations(instance)
                    if security_rec:
                        recommendations.append(security_rec)

                # 5. CPU 사용률 모니터링
                if instance.get('state') == 'running' and instance.get('cpu_metrics'):  # CpuMetrics -> cpu_metrics
                    cpu_rec = check_cpu_utilization(instance)
                    if cpu_rec:
                        recommendations.append(cpu_rec)

                # 6. EBS 볼륨 최적화
                if instance.get('volumes'):  # Volumes -> volumes
                    ebs_rec = check_ebs_optimization(instance)
                    if ebs_rec:
                        recommendations.append(ebs_rec)

                # 7. 태그 관리
                if instance.get('tags'):  # Tags -> tags
                    tag_rec = check_tag_recommendations(instance)
                    if tag_rec:
                        recommendations.append(tag_rec)

                # 8. 네트워크 성능 모니터링
                if instance.get('network_metrics'):  # NetworkMetrics -> network_metrics
                    network_rec = check_network_performance(instance)
                    if network_rec:
                        recommendations.append(network_rec)

                # 9. 백업 정책 검사
                if instance.get('id'):  # InstanceId -> id
                    backup_rec = check_backup_recommendations(instance)
                    if backup_rec:
                        recommendations.append(backup_rec)

            except Exception as e:
                logger.error(f"Error processing instance {instance_id}: {str(e)}")
                continue

        logger.info(f"Found {len(recommendations)} recommendations")
        return recommendations
        
    except Exception as e:
        logger.error(f"Error in get_ec2_recommendations: {str(e)}")
        return []