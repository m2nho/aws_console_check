import boto3
from datetime import datetime, timezone

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
            instance_info = {
                'id': instance['DBInstanceIdentifier'],
                'engine': instance['Engine'],
                'status': instance['DBInstanceStatus'],
                'size': instance['DBInstanceClass'],
                'storage': instance.get('AllocatedStorage', 0),
                'multi_az': instance.get('MultiAZ', False),
                'backup_retention': instance.get('BackupRetentionPeriod', 0),
                'encrypted': instance.get('StorageEncrypted', False),
                'performance_insights': instance.get('PerformanceInsightsEnabled', False),
                'auto_minor_version_upgrade': instance.get('AutoMinorVersionUpgrade', False),
                'publicly_accessible': instance.get('PubliclyAccessible', False)
            }
            
            # 태그 정보 수집
            try:
                tags = rds_client.list_tags_for_resource(
                    ResourceName=instance['DBInstanceArn']
                )
                instance_info['tags'] = tags.get('TagList', [])
            except:
                instance_info['tags'] = []
                
            instances.append(instance_info)
        return {'instances': instances}
    except Exception as e:
        return {'error': str(e)}

def get_rds_recommendations(instances):
    """RDS 인스턴스 추천 사항 수집"""
    recommendations = []
    
    for instance in instances:
        # 1. Aurora 마이그레이션 추천
        if not instance['id'].startswith('aurora-'):
            recommendations.append(create_aurora_recommendation(instance))
        
        # 2. 암호화 설정 검사
        if not instance['encrypted']:
            recommendations.append(create_encryption_recommendation(instance))
        
        # 3. 다중 AZ 배포 검사
        if not instance['multi_az']:
            recommendations.append(create_multi_az_recommendation(instance))
        
        # 4. 백업 보존 기간 검사
        if instance['backup_retention'] < 7:
            recommendations.append(create_backup_recommendation(instance))
        
        # 5. Performance Insights 활성화 검사
        if not instance['performance_insights']:
            recommendations.append(create_performance_insights_recommendation(instance))
        
        # 6. 자동 마이너 버전 업그레이드 검사
        if not instance['auto_minor_version_upgrade']:
            recommendations.append(create_auto_upgrade_recommendation(instance))
        
        # 7. 퍼블릭 액세스 검사
        if instance['publicly_accessible']:
            recommendations.append(create_public_access_recommendation(instance))
        
        # 8. 태그 관리 검사
        if not instance['tags']:
            recommendations.append(create_tagging_recommendation(instance))
    
    return recommendations

def create_aurora_recommendation(instance):
    """Aurora 마이그레이션 추천 사항 생성"""
    return {
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
        'benefit': "Aurora로 마이그레이션하면 성능이 향상되고, 자동 확장 기능을 활용할 수 있으며, 운영 오버헤드가 감소합니다."
    }

def create_encryption_recommendation(instance):
    """암호화 설정 추천 사항 생성"""
    return {
        'service': 'RDS',
        'resource': instance['id'],
        'severity': '높음',
        'message': f"RDS 인스턴스가 암호화되어 있지 않습니다. 데이터 보안을 위해 암호화를 활성화하세요.",
        'problem': f"RDS 인스턴스 {instance['id']}에 스토리지 암호화가 설정되어 있지 않습니다.",
        'impact': "암호화되지 않은 데이터베이스는 데이터 유출의 위험이 있습니다.",
        'steps': [
            "암호화되지 않은 DB 인스턴스의 스냅샷을 생성합니다.",
            "스냅샷의 암호화된 사본을 생성합니다.",
            "암호화된 스냅샷에서 새 DB 인스턴스를 복원합니다.",
            "애플리케이션 연결을 새 DB 인스턴스로 전환합니다.",
            "기존 DB 인스턴스를 삭제합니다."
        ],
        'benefit': "데이터베이스 암호화를 통해 저장된 데이터를 보호하고 규정 준수 요구사항을 충족할 수 있습니다."
    }

def create_multi_az_recommendation(instance):
    """다중 AZ 배포 추천 사항 생성"""
    return {
        'service': 'RDS',
        'resource': instance['id'],
        'severity': '높음',
        'message': f"RDS 인스턴스가 단일 AZ에서 실행 중입니다. 고가용성을 위해 다중 AZ 배포를 구성하세요.",
        'problem': f"RDS 인스턴스 {instance['id']}가 다중 AZ 구성으로 실행되지 않고 있습니다.",
        'impact': "단일 AZ 배포는 AZ 장애 시 서비스 중단의 위험이 있습니다.",
        'steps': [
            "AWS 콘솔에서 RDS 서비스로 이동합니다.",
            "대상 DB 인스턴스를 선택합니다.",
            "'수정'을 클릭합니다.",
            "'다중 AZ 배포' 옵션을 활성화합니다.",
            "변경 사항을 적용합니다."
        ],
        'benefit': "다중 AZ 배포를 통해 고가용성을 확보하고 계획된/계획되지 않은 유지 관리 시 다운타임을 최소화할 수 있습니다."
    }

def create_backup_recommendation(instance):
    """백업 보존 기간 추천 사항 생성"""
    return {
        'service': 'RDS',
        'resource': instance['id'],
        'severity': '중간',
        'message': f"백업 보존 기간이 7일 미만으로 설정되어 있습니다. 데이터 보호를 위해 보존 기간을 늘리세요.",
        'problem': f"RDS 인스턴스 {instance['id']}의 백업 보존 기간이 충분하지 않습니다.",
        'impact': "짧은 백업 보존 기간은 장기간의 데이터 복구 능력을 제한합니다.",
        'steps': [
            "AWS 콘솔에서 RDS 서비스로 이동합니다.",
            "대상 DB 인스턴스를 선택합니다.",
            "'수정'을 클릭합니다.",
            "'백업' 섹션에서 보존 기간을 7일 이상으로 설정합니다.",
            "변경 사항을 적용합니다."
        ],
        'benefit': "충분한 백업 보존 기간을 통해 더 긴 기간의 시점 복구가 가능하며, 데이터 손실 위험을 줄일 수 있습니다."
    }

def create_performance_insights_recommendation(instance):
    """Performance Insights 활성화 추천 사항 생성"""
    return {
        'service': 'RDS',
        'resource': instance['id'],
        'severity': '낮음',
        'message': f"Performance Insights가 비활성화되어 있습니다. 데이터베이스 성능 모니터링을 위해 활성화하세요.",
        'problem': f"RDS 인스턴스 {instance['id']}에 Performance Insights가 활성화되어 있지 않습니다.",
        'impact': "성능 문제 발생 시 원인 파악과 분석이 어려울 수 있습니다.",
        'steps': [
            "AWS 콘솔에서 RDS 서비스로 이동합니다.",
            "대상 DB 인스턴스를 선택합니다.",
            "'수정'을 클릭합니다.",
            "'Performance Insights' 섹션에서 기능을 활성화합니다.",
            "보존 기간 및 암호화 설정을 구성합니다."
        ],
        'benefit': "Performance Insights를 통해 데이터베이스 성능 문제를 쉽게 발견하고 분석할 수 있습니다."
    }

def create_auto_upgrade_recommendation(instance):
    """자동 마이너 버전 업그레이드 추천 사항 생성"""
    return {
        'service': 'RDS',
        'resource': instance['id'],
        'severity': '중간',
        'message': f"자동 마이너 버전 업그레이드가 비활성화되어 있습니다. 보안 패치 적용을 위해 활성화하세요.",
        'problem': f"RDS 인스턴스 {instance['id']}에 자동 마이너 버전 업그레이드가 비활성화되어 있습니다.",
        'impact': "보안 패치와 버그 수정이 자동으로 적용되지 않아 보안 위험이 있을 수 있습니다.",
        'steps': [
            "AWS 콘솔에서 RDS 서비스로 이동합니다.",
            "대상 DB 인스턴스를 선택합니다.",
            "'수정'을 클릭합니다.",
            "'마이너 버전 자동 업그레이드' 옵션을 활성화합니다.",
            "변경 사항을 적용합니다."
        ],
        'benefit': "자동 마이너 버전 업그레이드를 통해 최신 보안 패치와 버그 수정을 자동으로 적용받을 수 있습니다."
    }

def create_public_access_recommendation(instance):
    """퍼블릭 액세스 제한 추천 사항 생성"""
    return {
        'service': 'RDS',
        'resource': instance['id'],
        'severity': '높음',
        'message': f"RDS 인스턴스가 퍼블릭하게 접근 가능하도록 설정되어 있습니다. 보안을 위해 접근을 제한하세요.",
        'problem': f"RDS 인스턴스 {instance['id']}가 퍼블릭 액세스가 가능하도록 설정되어 있습니다.",
        'impact': "데이터베이스가 인터넷을 통해 접근 가능하여 보안 위험이 있습니다.",
        'steps': [
            "AWS 콘솔에서 RDS 서비스로 이동합니다.",
            "대상 DB 인스턴스를 선택합니다.",
            "'수정'을 클릭합니다.",
            "'퍼블릭 액세스' 옵션을 비활성화합니다.",
            "보안 그룹 설정을 검토하고 필요한 접근만 허용하도록 수정합니다."
        ],
        'benefit': "데이터베이스를 프라이빗 서브넷에서만 접근 가능하도록 설정하여 보안을 강화할 수 있습니다."
    }

def create_tagging_recommendation(instance):
    """태그 관리 추천 사항 생성"""
    return {
        'service': 'RDS',
        'resource': instance['id'],
        'severity': '낮음',
        'message': f"RDS 인스턴스에 태그가 설정되어 있지 않습니다. 리소스 관리를 위해 태그를 추가하세요.",
        'problem': f"RDS 인스턴스 {instance['id']}에 태그가 설정되어 있지 않습니다.",
        'impact': "태그가 없으면 리소스 관리, 비용 할당 및 보안 감사가 어려울 수 있습니다.",
        'steps': [
            "AWS 콘솔에서 RDS 서비스로 이동합니다.",
            "대상 DB 인스턴스를 선택합니다.",
            "'태그' 탭을 선택합니다.",
            "'태그 관리'를 클릭합니다.",
            "필요한 태그를 추가합니다. (예: Environment, Owner, Cost Center 등)"
        ],
        'benefit': "태그를 통해 리소스를 효율적으로 관리하고, 비용을 추적하며, 보안 정책을 적용할 수 있습니다."
    }
