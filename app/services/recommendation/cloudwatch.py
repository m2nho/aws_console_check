import boto3
from datetime import datetime, timezone

def get_cloudwatch_recommendations(monitoring_data):
    """CloudWatch 추천 사항 수집"""
    recommendations = []
    
    if isinstance(monitoring_data, dict) and monitoring_data.get('error'):
        return recommendations
    
    alarms = monitoring_data.get('alarms', []) if isinstance(monitoring_data, dict) else []
    metrics = monitoring_data.get('metrics', []) if isinstance(monitoring_data, dict) else []
    dashboards = monitoring_data.get('dashboards', []) if isinstance(monitoring_data, dict) else []
    
    # 1. 기본 경보 부족 검사
    if len(alarms) < 3:
        recommendations.append(create_basic_alarms_recommendation())
    
    # 2. 경보 작업 구성 검사
    for alarm in alarms:
        if isinstance(alarm, dict):
            if not alarm.get('actions_enabled') or not alarm.get('alarm_actions'):
                recommendations.append(create_alarm_actions_recommendation(alarm))
    
    # 3. 메트릭 네임스페이스 검사
    namespaces = set()
    for metric in metrics:
        if isinstance(metric, dict):
            namespace = metric.get('namespace')
            if namespace:
                namespaces.add(namespace)
    
    critical_namespaces = {'AWS/EC2', 'AWS/RDS', 'AWS/Lambda'}
    missing_namespaces = critical_namespaces - namespaces
    if missing_namespaces:
        recommendations.append(create_missing_metrics_recommendation(missing_namespaces))
    
    # 4. 대시보드 구성 검사
    if len(dashboards) < 1:
        recommendations.append(create_dashboard_recommendation())
    
    return recommendations
def create_basic_alarms_recommendation():
    """기본 경보 구성 추천 사항 생성"""
    return {
        'service': 'CloudWatch',
        'resource': 'Alarms',
        'severity': '높음',
        'message': "기본적인 모니터링 경보가 충분하지 않습니다.",
        'problem': "현재 설정된 CloudWatch 경보의 수가 최소 권장 수준 미만입니다.",
        'impact': "시스템 문제 발생 시 적시에 탐지하지 못할 수 있습니다.",
        'steps': [
            "EC2 인스턴스의 CPU 사용률, 메모리 사용률에 대한 경보를 설정합니다.",
            "RDS 인스턴스의 연결 수, 디스크 사용량에 대한 경보를 설정합니다.",
            "애플리케이션의 오류율과 지연 시간에 대한 경보를 설정합니다.",
            "각 경보에 대한 적절한 임계값을 설정합니다.",
            "경보 발생 시 알림을 받을 SNS 주제를 구성합니다."
        ],
        'benefit': "주요 메트릭에 대한 경보를 설정하여 시스템 문제를 조기에 발견하고 대응할 수 있습니다."
    }

def create_alarm_actions_recommendation(alarm):
    """경보 작업 구성 추천 사항 생성"""
    alarm_name = alarm.get('name', 'Unknown')
    return {
        'service': 'CloudWatch',
        'resource': alarm_name,
        'severity': '중간',
        'message': f"경보 '{alarm_name}'에 대한 작업이 구성되지 않았습니다.",
        'problem': "경보가 트리거될 때 실행할 작업이 설정되지 않았거나 비활성화되어 있습니다.",
        'impact': "경보 발생 시 적절한 대응 조치가 자동으로 실행되지 않을 수 있습니다.",
        'steps': [
            "AWS 콘솔에서 CloudWatch 서비스로 이동합니다.",
            "경보 섹션에서 해당 경보를 선택합니다.",
            "경보 편집을 클릭합니다.",
            "SNS 주제를 생성하거나 선택하여 알림을 구성합니다.",
            "필요한 경우 Auto Scaling 또는 EC2 작업을 구성합니다.",
            "변경 사항을 저장합니다."
        ],
        'benefit': "경보 발생 시 자동화된 대응을 통해 신속하게 문제를 해결할 수 있습니다."
    }


def create_missing_metrics_recommendation(missing_namespaces):
    """누락된 메트릭 추천 사항 생성"""
    return {
        'service': 'CloudWatch',
        'resource': 'Metrics',
        'severity': '중간',
        'message': "중요한 AWS 서비스의 메트릭이 수집되지 않고 있습니다.",
        'problem': f"다음 네임스페이스의 메트릭이 누락되었습니다: {', '.join(missing_namespaces)}",
        'impact': "중요한 서비스의 상태와 성능을 모니터링하지 못할 수 있습니다.",
        'steps': [
            "AWS 콘솔에서 CloudWatch 서비스로 이동합니다.",
            "해당 서비스의 세부 모니터링을 활성화합니다.",
            "필요한 경우 CloudWatch 에이전트를 설치합니다.",
            "커스텀 메트릭 수집을 구성합니다.",
            "수집된 메트릭에 대한 경보를 설정합니다."
        ],
        'benefit': "모든 중요 서비스의 메트릭을 수집하여 종합적인 모니터링이 가능합니다."
    }

def create_dashboard_recommendation():
    """대시보드 구성 추천 사항 생성"""
    return {
        'service': 'CloudWatch',
        'resource': 'Dashboards',
        'severity': '낮음',
        'message': "CloudWatch 대시보드가 구성되지 않았습니다.",
        'problem': "시스템 상태를 한눈에 파악할 수 있는 대시보드가 없습니다.",
        'impact': "시스템 모니터링과 문제 진단이 비효율적일 수 있습니다.",
        'steps': [
            "AWS 콘솔에서 CloudWatch 서비스로 이동합니다.",
            "대시보드 생성을 클릭합니다.",
            "주요 메트릭을 위젯으로 추가합니다.",
            "위젯을 논리적으로 그룹화하여 배치합니다.",
            "대시보드를 저장하고 필요한 사용자와 공유합니다."
        ],
        'benefit': "통합된 대시보드를 통해 시스템 상태를 효율적으로 모니터링할 수 있습니다."
    }

