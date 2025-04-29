import boto3

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
            buckets.append({
                'name': bucket['Name'],
                'creation_date': bucket['CreationDate'].strftime('%Y-%m-%d')
            })
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
            try:
                lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket['name'])
                if not lifecycle.get('Rules'):
                    recommendations.append(create_lifecycle_recommendation(bucket['name']))
            except:
                recommendations.append(create_lifecycle_recommendation(bucket['name']))
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
        'benefit': "수명 주기 규칙을 설정하면 자주 액세스하지 않는 객체를 자동으로 저비용 스토리지 클래스로 이동하거나 불필요한 객체를 삭제하여 스토리지 비용을 절감할 수 있습니다.",
        'links': [
            {'url': 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-configuration-examples.html', 'title': 'S3 수명 주기 구성 예제'},
            {'url': 'https://aws.amazon.com/blogs/aws/amazon-s3-object-lifecycle-management/', 'title': 'S3 객체 수명 주기 관리 블로그'}
        ]
    }