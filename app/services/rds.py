import boto3

def get_rds_data(aws_access_key, aws_secret_key, region):
    """RDS 인스턴스 데이터 수집"""
    try:
        rds_client = boto3.client(
            'rds',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        response = rds_client.describe_db_instances()
        instances = []
        for instance in response['DBInstances']:
            instances.append({
                'id': instance['DBInstanceIdentifier'],
                'engine': instance['Engine'],
                'status': instance['DBInstanceStatus'],
                'size': instance['DBInstanceClass']
            })
        return {'instances': instances}
    except Exception as e:
        return {'error': str(e)}

def get_rds_recommendations(instances):
    """RDS 인스턴스 추천 사항 수집"""
    recommendations = []
    
    for instance in instances:
        if not instance['id'].startswith('aurora-'):
            recommendations.append({
                'service': 'RDS',
                'resource': instance['id'],
                'severity': '중간',
                'message': f"RDS 인스턴스는 Aurora로 마이그레이션하여 성능과 비용 효율성을 개선할 수 있습니다.",
                'problem': f"RDS 인스턴스 {instance['id']}가 Aurora가 아닌 {instance['engine']} 엔진을 사용하고 있습니다.",
                'impact': "Aurora는 기존 MySQL 및 PostgreSQL 데이터베이스보다 최대 5배 향상된 성능과 향상된 가용성을 제공합니다.",
                'steps': [
                    "AWS 콘솔에서 RDS 서비스로 이동합니다.",
                    "스냅샷을 생성하여 현재 데이터베이스를 백업합니다.",
                    "스냅샷에서 Aurora 데이터베이스로 복원합니다.",
                    "애플리케이션 연결 문자열을 새 Aurora 엔드포인트로 업데이트합니다.",
                    "마이그레이션이 완료되면 원본 RDS 인스턴스를 삭제합니다."
                ],
                'benefit': "Aurora로 마이그레이션하면 성능이 향상되고, 자동 확장 기능을 활용할 수 있으며, 운영 오버헤드가 감소합니다.",
                'links': [
                    {'url': 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Aurora.Migrating.html', 'title': 'Aurora로 마이그레이션 가이드'},
                    {'url': 'https://aws.amazon.com/rds/aurora/', 'title': 'Amazon Aurora 소개'}
                ]
            })
    
    return recommendations