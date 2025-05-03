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
