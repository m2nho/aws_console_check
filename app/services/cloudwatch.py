import boto3

def get_cloudwatch_data(aws_access_key, aws_secret_key, region):
    """CloudWatch 경보 데이터 수집"""
    try:
        cloudwatch_client = boto3.client(
            'cloudwatch',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        response = cloudwatch_client.describe_alarms()
        alarms = []
        for alarm in response['MetricAlarms']:
            alarms.append({
                'name': alarm['AlarmName'],
                'state': alarm['StateValue'],
                'metric': alarm['MetricName']
            })
        return {'alarms': alarms}
    except Exception as e:
        return {'error': str(e)}

def get_cloudwatch_recommendations(alarms):
    """CloudWatch 경보 추천 사항 수집"""
    recommendations = []
    
    if len(alarms) < 3:
        recommendations.append({
            'service': 'CloudWatch',
            'resource': 'All',
            'severity': '높음',
            'message': "중요한 리소스에 대한 CloudWatch 경보가 충분하지 않습니다. 주요 지표에 대한 경보를 추가하세요.",
            'problem': "현재 CloudWatch 경보가 3개 미만으로 설정되어 있어, 중요한 리소스에 대한 모니터링이 부족할 수 있습니다.",
            'impact': "충분한 경보가 없으면 시스템 문제를 조기에 감지하지 못해 서비스 중단이나 성능 저하가 발생할 수 있습니다.",
            'steps': [
                "EC2 인스턴스의 CPU 사용률, 메모리 사용률, 디스크 공간에 대한 경보를 설정합니다.",
                "RDS 데이터베이스의 CPU 사용률, 여유 스토리지 공간, 연결 수에 대한 경보를 설정합니다.",
                "Lambda 함수의 오류율, 지연 시간에 대한 경보를 설정합니다.",
                "API Gateway의 4xx, 5xx 오류에 대한 경보를 설정합니다.",
                "경보 알림을 SNS 주제에 연결하여 이메일 또는 SMS로 알림을 받도록 설정합니다."
            ],
            'benefit': "적절한 경보를 설정하면 문제를 조기에 감지하고 대응하여 서비스 가용성과 성능을 향상시킬 수 있습니다.",
            'links': [
                {'url': 'https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html', 'title': 'CloudWatch 경보 생성 가이드'},
                {'url': 'https://aws.amazon.com/cloudwatch/pricing/', 'title': 'CloudWatch 요금 정보'}
            ]
        })
    
    return recommendations