# app/services/ec2_checks/cpu_utilization.py
# Check for CPU utilization recommendations

import logging
from .utils import analyze_cpu_metrics

# 로깅 설정
logger = logging.getLogger(__name__)

def check_cpu_utilization(instance):
    """CPU 사용률 모니터링
    
    CPU 사용률 패턴을 분석하여 다음과 같은 상태를 확인합니다:
    - 매우 낮음 (20% 미만)
    - 적정 (20-80%)
    - 높음 (80% 이상)
    """
    # 상수 정의
    CPU_THRESHOLD = {
        'VERY_LOW': 20,
        'HIGH': 80,
        'MONITORING_DAYS': 7
    }

    try:
        instance_id = instance.get('id')
        logger.debug(f"Checking CPU utilization for instance {instance_id}")

        if not (instance['state'] == 'running' and instance.get('cpu_metrics')):
            logger.debug(f"Instance {instance_id} is not running or has no CPU metrics")
            return None

        cpu_stats = analyze_cpu_metrics(instance['cpu_metrics'])
        logger.debug(f"CPU stats for instance {instance_id}: {cpu_stats}")

        # CPU 사용 패턴 분석
        def get_cpu_pattern():
            if cpu_stats['low_usage_days'] >= CPU_THRESHOLD['MONITORING_DAYS']:
                return {
                    'pattern': 'under_utilized',
                    'days': cpu_stats['low_usage_days'],
                    'threshold': CPU_THRESHOLD['VERY_LOW'],
                    'recommendation': {
                        'message': f"CPU 사용률이 {cpu_stats['low_usage_days']}일 연속 {CPU_THRESHOLD['VERY_LOW']}% 미만으로 유지되고 있습니다.",
                        'severity': '중간',
                        'steps': [
                            "CloudWatch 메트릭을 검토합니다.",
                            "인스턴스 다운사이징을 검토합니다.",
                            "예약 인스턴스 전환을 검토합니다.",
                            "자동 중지/시작 스케줄링을 고려합니다."
                        ],
                        'problem': "지속적으로 낮은 CPU 사용률이 발생하고 있습니다.",
                        'impact': "과다 프로비저닝으로 인한 불필요한 비용이 발생하고 있습니다.",
                        'benefit': "적절한 크기 조정으로 최대 30-50% 비용 절감이 가능합니다."
                    }
                }
            elif cpu_stats['high_usage_days'] >= CPU_THRESHOLD['MONITORING_DAYS']:
                return {
                    'pattern': 'over_utilized',
                    'days': cpu_stats['high_usage_days'],
                    'threshold': CPU_THRESHOLD['HIGH'],
                    'recommendation': {
                        'message': f"CPU 사용률이 {cpu_stats['high_usage_days']}일 연속 {CPU_THRESHOLD['HIGH']}% 이상으로 유지되고 있습니다.",
                        'severity': '높음',
                        'steps': [
                            "CloudWatch 메트릭을 상세 분석합니다.",
                            "인스턴스 업스케일링을 검토합니다.",
                            "Auto Scaling 구성을 검토합니다.",
                            "워크로드 분산 방안을 검토합니다."
                        ],
                        'problem': "지속적으로 높은 CPU 사용률이 발생하고 있습니다.",
                        'impact': "성능 병목 현상으로 서비스 지연이 발생할 수 있습니다.",
                        'benefit': "적절한 리소스 확장으로 안정적인 서비스 제공이 가능합니다."
                    }
                }
            return None

        cpu_pattern = get_cpu_pattern()
        if not cpu_pattern:
            logger.debug(f"No significant CPU utilization pattern found for instance {instance_id}")
            return None

        # 결과 반환
        return {
            'service': 'EC2',
            'resource': instance_id,
            'message': cpu_pattern['recommendation']['message'],
            'severity': cpu_pattern['recommendation']['severity'],
            'steps': cpu_pattern['recommendation']['steps'],
            'problem': cpu_pattern['recommendation']['problem'],
            'impact': cpu_pattern['recommendation']['impact'],
            'benefit': cpu_pattern['recommendation']['benefit'],
            'metadata': {
                'pattern': cpu_pattern['pattern'],
                'days': cpu_pattern['days'],
                'threshold': cpu_pattern['threshold']
            }
        }

    except Exception as e:
        logger.error(f"Error in check_cpu_utilization for instance {instance_id}: {str(e)}", exc_info=True)
        return None