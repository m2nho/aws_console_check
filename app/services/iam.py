import boto3

def get_iam_data(aws_access_key, aws_secret_key, region):
    """IAM 사용자 데이터 수집"""
    try:
        iam_client = boto3.client(
            'iam',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        response = iam_client.list_users()
        users = []
        for user in response['Users']:
            users.append({
                'name': user['UserName'],
                'created': user['CreateDate'].strftime('%Y-%m-%d'),
                'id': user['UserId']
            })
        
        return {'users': users}
    except Exception as e:
        return {'error': str(e)}

def get_iam_recommendations(users):
    """IAM 사용자 추천 사항 수집"""
    recommendations = []
    
    if len(users) > 5:
        recommendations.append({
            'service': 'IAM',
            'resource': 'All',
            'severity': '높음',
            'message': "다수의 IAM 사용자가 있습니다. 미사용 계정을 정기적으로 검토하고 제거하세요.",
            'problem': f"현재 계정에 {len(users)}명의 IAM 사용자가 있습니다. 이는 보안 위험을 증가시킬 수 있습니다.",
            'impact': "사용하지 않는 IAM 사용자는 보안 위험을 초래하고 계정 관리를 복잡하게 만들 수 있습니다.",
            'steps': [
                "AWS 콘솔에서 IAM 서비스로 이동합니다.",
                "각 사용자의 마지막 활동 시간을 확인합니다.",
                "90일 이상 활동이 없는 사용자를 식별합니다.",
                "필요하지 않은 사용자를 비활성화하거나 삭제합니다.",
                "나머지 사용자에 대해 최소 권한 원칙을 적용합니다."
            ],
            'benefit': "미사용 계정을 제거하면 보안 위험이 감소하고 계정 관리가 간소화됩니다.",
            'links': [
                {'url': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_manage.html#id_users_deleting', 'title': 'IAM 사용자 삭제'},
                {'url': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html', 'title': 'IAM 모범 사례'}
            ]
        })
    
    return recommendations