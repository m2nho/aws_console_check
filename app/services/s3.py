import boto3
from datetime import datetime, timezone

def get_s3_data(aws_access_key, aws_secret_key, region):
    """S3 버킷 데이터 수집"""
    try:
        s3_client = boto3.client(
            's3',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        response = s3_client.list_buckets()
        buckets = []
        for bucket in response['Buckets']:
            bucket_info = {
                'name': bucket['Name'],
                'creation_date': bucket['CreationDate'].strftime('%Y-%m-%d')
            }
            
            # 버킷 버저닝 상태 확인
            try:
                versioning = s3_client.get_bucket_versioning(Bucket=bucket['XXXX'])
                bucket_info['versioning'] = versioning.get('Status', 'Disabled')
            except:
                bucket_info['versioning'] = 'Disabled'
            
            # 버킷 암호화 상태 확인
            try:
                encryption = s3_client.get_bucket_encryption(Bucket=bucket['XXXX'])
                bucket_info['encryption'] = True
            except:
                bucket_info['encryption'] = False
            
            # 퍼블릭 액세스 설정 확인
            try:
                public_access = s3_client.get_public_access_block(Bucket=bucket['Name'])
                bucket_info['public_access_blocked'] = all([
                    public_access['PublicAccessBlockConfiguration']['BlockPublicAcls'],
                    public_access['PublicAccessBlockConfiguration']['IgnorePublicAcls'],
                    public_access['PublicAccessBlockConfiguration']['BlockPublicPolicy'],
                    public_access['PublicAccessBlockConfiguration']['RestrictPublicBuckets']
                ])
            except:
                bucket_info['public_access_blocked'] = False
            
            buckets.append(bucket_info)
        return {'buckets': buckets}
    except Exception as e:
        return {'error': str(e)}

def get_s3_recommendations(buckets, aws_access_key, aws_secret_key, region):
    """S3 버킷 추천 사항 수집"""
    recommendations = []
    
    try:
        s3_client = boto3.client(
            's3',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        for bucket in buckets:
            # 1. 수명 주기 규칙 검사
            try:
                lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket['XXXX'])
                if not lifecycle.get('Rules'):
                    recommendations.append(create_lifecycle_recommendation(bucket['name']))
            except:
                recommendations.append(create_lifecycle_recommendation(bucket['name']))
            
            # 2. 버저닝 검사
            if bucket.get('versioning') != 'Enabled':
                recommendations.append(create_versioning_recommendation(bucket['name']))
            
            # 3. 암호화 검사
            if not bucket.get('encryption'):
                recommendations.append(create_encryption_recommendation(bucket['name']))
            
            # 4. 퍼블릭 액세스 검사
            if not bucket.get('public_access_blocked'):
                recommendations.append(create_public_access_recommendation(bucket['name']))
            
            # 5. 인벤토리 설정 검사
            try:
                inventory = s3_client.list_bucket_inventory_configurations(Bucket=bucket['XXXX'])
                if not inventory.get('InventoryConfigurationList'):
                    recommendations.append(create_inventory_recommendation(bucket['name']))
            except:
                recommendations.append(create_inventory_recommendation(bucket['name']))

    except Exception as e:
        print(f"Error in S3 recommendations: {str(e)}")
    
    return recommendations

def create_lifecycle_recommendation(bucket_name):
    """S3 수명 주기 규칙 추천 사항 생성"""
    return {
        'service': 'S3',
        'resource': bucket_name,
        'severity': '중간',
        'message': f"버킷에 수명 주기 규칙이 없습니다. 비용 절감을 위해 수명 주기 규칙을 설정하세요.",
        'problem': f"S3 버킷 {bucket_name}에 수명 주기 규칙이 설정되어 있지 않습니다.",
        'impact': "수명 주기 규칙이 없으면 오래된 객체가 자동으로 저비용 스토리지 클래스로 이동하거나 삭제되지 않아 불필요한 비용이 발생할 수 있습니다.",
        'steps': [
            "AWS 콘솔에서 S3 서비스로 이동합니다.",
            f"버킷 {bucket_name}을 선택합니다.",
            "'관리' 탭을 클릭합니다.",
            "'수명 주기 규칙'에서 '규칙 생성'을 클릭합니다.",
            "객체의 사용 패턴에 따라 적절한 전환 및 만료 규칙을 설정합니다."
        ],
        'benefit': "수명 주기 규칙을 설정하면 자주 액세스하지 않는 객체를 자동으로 저비용 스토리지 클래스로 이동하거나 불필요한 객체를 삭제하여 스토리지 비용을 절감할 수 있습니다."
    }

def create_versioning_recommendation(bucket_name):
    """S3 버저닝 추천 사항 생성"""
    return {
        'service': 'S3',
        'resource': bucket_name,
        'severity': '높음',
        'message': f"버킷에 버전 관리가 비활성화되어 있습니다. 데이터 보호를 위해 버전 관리를 활성화하세요.",
        'problem': f"S3 버킷 {bucket_name}에 버전 관리가 활성화되어 있지 않습니다.",
        'impact': "버전 관리가 비활성화되면 실수로 인한 객체 삭제나 덮어쓰기로부터 데이터를 보호할 수 없습니다.",
        'steps': [
            "AWS 콘솔에서 S3 서비스로 이동합니다.",
            f"버킷 {bucket_name}을 선택합니다.",
            "'속성' 탭을 클릭합니다.",
            "'버킷 버전 관리' 섹션에서 '편집'을 클릭합니다.",
            "버전 관리를 활성화합니다."
        ],
        'benefit': "버전 관리를 활성화하면 실수로 인한 데이터 손실을 방지하고, 이전 버전의 객체를 복구할 수 있습니다."
    }

def create_encryption_recommendation(bucket_name):
    """S3 암호화 추천 사항 생성"""
    return {
        'service': 'S3',
        'resource': bucket_name,
        'severity': '높음',
        'message': f"버킷에 기본 암호화가 설정되어 있지 않습니다. 데이터 보안을 위해 암호화를 활성화하세요.",
        'problem': f"S3 버킷 {bucket_name}에 기본 암호화가 설정되어 있지 않습니다.",
        'impact': "암호화가 설정되지 않은 경우 저장된 데이터가 보안 위험에 노출될 수 있습니다.",
        'steps': [
            "AWS 콘솔에서 S3 서비스로 이동합니다.",
            f"버킷 {bucket_name}을 선택합니다.",
            "'속성' 탭을 클릭합니다.",
            "'기본 암호화' 섹션에서 '편집'을 클릭합니다.",
            "SSE-S3 또는 SSE-KMS 암호화를 활성화합니다."
        ],
        'benefit': "기본 암호화를 설정하면 버킷에 업로드되는 모든 새로운 객체가 자동으로 암호화되어 데이터 보안이 강화됩니다."
    }

def create_public_access_recommendation(bucket_name):
    """S3 퍼블릭 액세스 차단 추천 사항 생성"""
    return {
        'service': 'S3',
        'resource': bucket_name,
        'severity': '높음',
        'message': f"버킷의 퍼블릭 액세스 차단 설정이 완전하지 않습니다. 보안 강화를 위해 모든 퍼블릭 액세스를 차단하세요.",
        'problem': f"S3 버킷 {bucket_name}의 퍼블릭 액세스 차단 설정이 불완전합니다.",
        'impact': "퍼블릭 액세스가 허용되면 버킷이나 객체가 의도치 않게 공개될 수 있습니다.",
        'steps': [
            "AWS 콘솔에서 S3 서비스로 이동합니다.",
            f"버킷 {bucket_name}을 선택합니다.",
            "'권한' 탭을 클릭합니다.",
            "'퍼블릭 액세스 차단' 섹션에서 '편집'을 클릭합니다.",
            "모든 퍼블릭 액세스 차단 옵션을 활성화합니다."
        ],
        'benefit': "퍼블릭 액세스를 차단하면 실수로 인한 데이터 노출을 방지하고 보안을 강화할 수 있습니다."
    }

def create_inventory_recommendation(bucket_name):
    """S3 인벤토리 설정 추천 사항 생성"""
    return {
        'service': 'S3',
        'resource': bucket_name,
        'severity': '낮음',
        'message': f"버킷에 인벤토리 설정이 없습니다. 객체 관리를 위해 인벤토리 설정을 구성하세요.",
        'problem': f"S3 버킷 {bucket_name}에 인벤토리 설정이 구성되어 있지 않습니다.",
        'impact': "인벤토리 설정이 없으면 버킷 내 객체의 현황을 파악하고 관리하기 어렵습니다.",
        'steps': [
            "AWS 콘솔에서 S3 서비스로 이동합니다.",
            f"버킷 {bucket_name}을 선택합니다.",
            "'관리' 탭을 클릭합니다.",
            "'인벤토리 구성'에서 '인벤토리 규칙 생성'을 클릭합니다.",
            "필요한 인벤토리 보고서 설정을 구성합니다."
        ],
        'benefit': "인벤토리를 설정하면 버킷 내 객체의 현황을 정기적으로 파악하고, 스토리지 최적화에 활용할 수 있습니다."
    }
