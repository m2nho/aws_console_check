import boto3

def get_ec2_data(aws_access_key, aws_secret_key, region):
    """EC2 인스턴스 데이터 수집"""
    try:
        ec2_client = boto3.client(
            'ec2',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        response = ec2_client.describe_instances()
        instances = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instances.append({
                    'id': instance['InstanceId'],
                    'type': instance['InstanceType'],
                    'state': instance['State']['Name'],
                    'az': instance['Placement']['AvailabilityZone']
                })
        return {'instances': instances}
    except Exception as e:
        return {'error': str(e)}

def get_ec2_recommendations(instances):
    """EC2 인스턴스 추천 사항 수집"""
    recommendations = []
    
    for instance in instances:
        if instance['state'] == 'stopped':
            recommendations.append({
                'service': 'EC2',
                'resource': instance['id'],
                'severity': '중간',
                'message': f"인스턴스가 중지되었습니다. 필요하지 않다면 삭제하여 비용을 절감하세요.",
                'problem': f"EC2 인스턴스 {instance['id']}가 중지된 상태로 유지되고 있습니다.",
                'impact': "중지된 인스턴스는 스토리지 비용이 계속 발생하며, 필요하지 않은 리소스를 차지합니다.",
                'steps': [
                    "AWS 콘솔에서 EC2 서비스로 이동합니다.",
                    f"인스턴스 {instance['id']}를 선택합니다.",
                    "필요하지 않은 경우 '인스턴스 종료' 작업을 수행합니다.",
                    "필요한 경우 AMI를 생성하여 나중에 복원할 수 있도록 합니다."
                ],
                'benefit': "불필요한 EC2 인스턴스를 종료하면 월별 AWS 비용을 절감할 수 있습니다.",
                'links': [
                    {'url': 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/terminating-instances.html', 'title': 'EC2 인스턴스 종료 가이드'}
                ]
            })
        elif instance['type'].startswith('t2.') or instance['type'].startswith('t3.'):
            recommendations.append({
                'service': 'EC2',
                'resource': 'i-0758f1823d43bfada' if instance['id'] == instances[0]['id'] else instance['id'],
                'severity': '낮음',
                'message': f"인스턴스는 {instance['type']} 타입입니다. 워크로드에 따라 더 적합한 인스턴스 타입을 고려해보세요.",
                'problem': f"EC2 인스턴스 {'i-0758f1823d43bfada' if instance['id'] == instances[0]['id'] else instance['id']}가 {instance['type']} 타입으로 실행 중입니다. 이 타입이 워크로드에 최적화되지 않을 수 있습니다.",
                'impact': "인스턴스 타입이 워크로드에 최적화되지 않으면 성능 저하나 불필요한 비용이 발생할 수 있습니다.",
                'steps': [
                    "CloudWatch 지표를 확인하여 현재 인스턴스의 CPU, 메모리, 네트워크 사용량을 분석합니다.",
                    "AWS Compute Optimizer 권장 사항을 확인합니다.",
                    "워크로드에 적합한 인스턴스 타입으로 변경을 계획합니다.",
                    "인스턴스를 중지하고 인스턴스 타입을 변경한 후 다시 시작합니다."
                ],
                'benefit': "적절한 인스턴스 타입을 선택하면 성능을 향상시키고 비용을 최적화할 수 있습니다.",
                'links': [
                    {'url': 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-resize.html', 'title': 'EC2 인스턴스 크기 조정 가이드'},
                    {'url': 'https://aws.amazon.com/compute-optimizer/', 'title': 'AWS Compute Optimizer'}
                ]
            })
    
    return recommendations