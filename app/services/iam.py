import boto3
from datetime import datetime, timezone

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
            # 사용자 상세 정보 수집
            user_info = {
                'name': user['UserName'],
                'created': user['CreateDate'].strftime('%Y-%m-%d'),
                'id': user['UserId'],
                'mfa_enabled': False,
                'access_keys': [],
                'password_enabled': False,
                'groups': []
            }
            
            # MFA 디바이스 확인
            try:
                mfa_devices = iam_client.list_mfa_devices(UserName=user['UserName'])
                user_info['mfa_enabled'] = len(mfa_devices['MFADevices']) > 0
            except Exception:
                pass

            # 액세스 키 정보 수집
            try:
                access_keys = iam_client.list_access_keys(UserName=user['UserName'])
                for key in access_keys['AccessKeyMetadata']:
                    last_used = None
                    try:
                        key_last_used = iam_client.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                        last_used = key_last_used['AccessKeyLastUsed'].get('LastUsedDate')
                    except Exception:
                        pass
                    
                    user_info['access_keys'].append({
                        'id': key['AccessKeyId'],
                        'created': key['CreateDate'],
                        'status': key['Status'],
                        'last_used': last_used
                    })
            except Exception:
                pass

            # 로그인 프로필 확인 (콘솔 액세스)
            try:
                iam_client.get_login_profile(UserName=user['UserName'])
                user_info['password_enabled'] = True
            except iam_client.exceptions.NoSuchEntityException:
                pass

            # 그룹 멤버십 확인
            try:
                groups = iam_client.list_groups_for_user(UserName=user['UserName'])
                user_info['groups'] = [g['GroupName'] for g in groups['Groups']]
            except Exception:
                pass

            users.append(user_info)
        
        return {'users': users}
    except Exception as e:
        return {'error': str(e)}

def get_iam_recommendations(users):
    """IAM 사용자 추천 사항 수집"""
    recommendations = []
    
    # 1. 사용자 수가 많은 경우 (15명 이상일 때만)
    if len(users) > 15:
        recommendations.append(create_user_count_recommendation(users))
    
    # 2. MFA 관련 추천사항 (콘솔 액세스가 있는 사용자만)
    for user in users:
        if user['password_enabled'] and not user['mfa_enabled']:
            recommendations.append(create_mfa_recommendation(user))
    
    # 3. 액세스 키 관련 추천사항
    for user in users:
        access_key_rec = check_access_keys(user)
        if access_key_rec:
            recommendations.append(access_key_rec)
    
    # 4. 권한 경계 설정 (관리자 권한을 가진 사용자만)
    admin_users = []
    for user in users:
        if has_admin_access(user):
            admin_users.append(user)
            
    if admin_users:
        recommendations.append(create_permissions_boundary_recommendation(admin_users))
    
    # 5. 비밀번호 정책 (콘솔 액세스가 있는 사용자가 있을 때만)
    if any(user['password_enabled'] for user in users):
        recommendations.append(create_password_policy_recommendation())
    
    return recommendations

def has_admin_access(user):
    """사용자가 관리자 권한을 가지고 있는지 확인"""
    # 관리자 그룹 목록 확장
    admin_groups = [
        'Administrators',
        'Admin',
        'PowerUsers',
        'AdminGroup',
        'Administrator',
        'AWS-Admin',
        'SystemAdministrator'
    ]
    
    # 그룹 기반 체크
    if any(group in admin_groups for group in user['groups']):
        return True
        
    # IAM 클라이언트를 통해 사용자의 정책 확인
    try:
        iam_client = boto3.client('iam')
        
        # 직접 연결된 정책 확인
        attached_policies = iam_client.list_attached_user_policies(
            UserName=user['name']
        )['AttachedPolicies']
        
        # 인라인 정책 확인
        inline_policies = iam_client.list_user_policies(
            UserName=user['name']
        )['PolicyNames']
        
        # 관리자 권한이 있는 정책 목록
        admin_policies = [
            'AdministratorAccess',
            'IAMFullAccess',
            'PowerUserAccess'
        ]
        
        # 직접 연결된 정책에서 관리자 권한 확인
        for policy in attached_policies:
            if policy['PolicyName'] in admin_policies:
                return True
                
            # 정책 상세 내용 확인
            policy_version = iam_client.get_policy_version(
                PolicyArn=policy['PolicyArn'],
                VersionId=iam_client.get_policy(PolicyArn=policy['PolicyArn'])['Policy']['DefaultVersionId']
            )['PolicyVersion']
            
            # Effect: Allow, Action: *, Resource: * 패턴 확인
            for statement in policy_version['Document']['Statement']:
                if (statement.get('Effect') == 'Allow' and 
                    statement.get('Action') == '*' and 
                    statement.get('Resource') == '*'):
                    return True
        
        # 인라인 정책 확인
        for policy_name in inline_policies:
            policy = iam_client.get_user_policy(
                UserName=user['name'],
                PolicyName=policy_name
            )['PolicyDocument']
            
            # Effect: Allow, Action: *, Resource: * 패턴 확인
            for statement in policy['Statement']:
                if (statement.get('Effect') == 'Allow' and 
                    statement.get('Action') == '*' and 
                    statement.get('Resource') == '*'):
                    return True
                    
        return False
        
    except Exception as e:
        print(f"Error checking admin access for user {user['name']}: {str(e)}")
        return False

def check_access_keys(user):
    """액세스 키 상태 확인 및 추천사항 생성"""
    if not user['access_keys']:
        return None

    current_time = datetime.now(timezone.utc)
    old_keys = []
    inactive_keys = []
    
    for key in user['access_keys']:
        # 90일 이상 된 키 확인
        key_age = (current_time - key['created'].replace(tzinfo=timezone.utc)).days
        if key_age > 90:
            old_keys.append(key['id'])
        
        # 30일 이상 사용하지 않은 키 확인
        if key['last_used'] and (current_time - key['last_used'].replace(tzinfo=timezone.utc)).days > 30:
            inactive_keys.append(key['id'])
    
    if old_keys or inactive_keys:
        return create_access_key_recommendation(user['name'], old_keys, inactive_keys)
    
    return None

def create_user_count_recommendation(users):
    """사용자 수 관련 추천 사항 생성"""
    return {
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
        'benefit': "미사용 계정을 제거하면 보안 위험이 감소하고 계정 관리가 간소화됩니다."
    }

def create_mfa_recommendation(user):
    """MFA 관련 추천 사항 생성"""
    return {
        'service': 'IAM',
        'resource': user['name'],
        'severity': '높음',
        'message': f"사용자 {user['name']}에 대해 MFA 활성화가 필요합니다.",
        'problem': "콘솔 액세스가 가능한 IAM 사용자 계정에 MFA가 설정되어 있지 않습니다.",
        'impact': "MFA가 없는 계정은 비인가 접근에 취약할 수 있습니다.",
        'steps': [
            "AWS 콘솔에서 IAM 서비스로 이동합니다.",
            f"사용자 {user['name']}를 선택합니다.",
            "보안 자격 증명 탭으로 이동합니다.",
            "MFA 디바이스를 할당합니다.",
            "가상 MFA 또는 하드웨어 MFA를 설정합니다."
        ],
        'benefit': "MFA를 사용하면 계정 보안이 크게 강화됩니다."
    }

def create_access_key_recommendation(username, old_keys, inactive_keys):
    """액세스 키 관련 추천 사항 생성"""
    problems = []
    if old_keys:
        problems.append(f"90일 이상 된 액세스 키가 있습니다: {', '.join(old_keys)}")
    if inactive_keys:
        problems.append(f"30일 이상 사용하지 않은 액세스 키가 있습니다: {', '.join(inactive_keys)}")

    return {
        'service': 'IAM',
        'resource': username,
        'severity': '중간',
        'message': f"사용자 {username}의 액세스 키 관리가 필요합니다.",
        'problem': ' '.join(problems),
        'impact': "오래되거나 미사용 중인 액세스 키는 보안 위험을 초래할 수 있습니다.",
        'steps': [
            "AWS 콘솔에서 IAM 서비스로 이동합니다.",
            f"사용자 {username}를 선택합니다.",
            "보안 자격 증명 탭에서 액세스 키를 확인합니다.",
            "필요한 경우 새로운 액세스 키를 생성합니다.",
            "이전 키를 비활성화하고 일정 기간 후 삭제합니다."
        ],
        'benefit': "정기적인 키 관리는 보안을 강화하고 잠재적인 위험을 감소시킵니다."
    }

def create_permissions_boundary_recommendation(admin_users):
    """권한 경계 관련 추천 사항 생성"""
    return {
        'service': 'IAM',
        'resource': 'All',
        'severity': '중간',
        'message': "관리자 권한을 가진 사용자에 대한 권한 경계 설정이 필요합니다.",
        'problem': f"다음 사용자들이 관리자 권한을 가지고 있습니다: {', '.join([u['name'] for u in admin_users])}",
        'impact': "권한 경계가 없으면 관리자 권한을 가진 사용자가 의도하지 않게 과도한 권한을 행사할 수 있습니다.",
        'steps': [
            "AWS 콘솔에서 IAM 서비스로 이동합니다.",
            "적절한 권한 경계 정책을 생성합니다.",
            "식별된 관리자 사용자들에게 권한 경계를 적용합니다.",
            "정기적으로 권한 경계 설정을 검토합니다."
        ],
        'benefit': "권한 경계를 통해 관리자 권한의 남용을 방지하고 보안을 강화할 수 있습니다."
    }

def create_password_policy_recommendation():
    """비밀번호 정책 관련 추천 사항 생성"""
    return {
        'service': 'IAM',
        'resource': 'All',
        'severity': '중간',
        'message': "계정의 비밀번호 정책을 강화하세요.",
        'problem': "약한 비밀번호 정책은 보안 위험을 초래할 수 있습니다.",
        'impact': "취약한 비밀번호는 무단 접근의 위험을 증가시킵니다.",
        'steps': [
            "최소 14자 이상의 비밀번호 길이를 요구합니다.",
            "대문자, 소문자, 숫자, 특수문자를 포함하도록 설정합니다.",
            "비밀번호 재사용을 제한합니다.",
            "90일마다 비밀번호 변경을 요구합니다.",
            "이전 비밀번호 재사용을 방지합니다."
        ],
        'benefit': "강력한 비밀번호 정책은 계정 보안의 기본이 됩니다."
    }
