# app/services/ec2_checks/backup_recommendations.py
# Check for backup recommendations

import boto3
import logging

# 로깅 설정
logger = logging.getLogger(__name__)

def check_backup_recommendations(instance):
    """백업 정책 검사"""
    try:
        # AWS Backup 정책 확인
        backup = boto3.client('backup')
        
        # First, list all backup plans
        try:
            backup_plans = backup.list_backup_plans()
            
            has_backup = False
            for plan in backup_plans.get('BackupPlansList', []):
                try:
                    # Get selections for each backup plan
                    selections = backup.list_backup_selections(
                        BackupPlanId=plan['BackupPlanId']
                    )
                    
                    # Check if instance is covered by any selection
                    for selection in selections.get('BackupSelectionsList', []):
                        # Check if instance is directly selected
                        if instance['InstanceId'] in selection.get('Resources', []):
                            has_backup = True
                            break
                            
                        # Check if instance is selected by tags
                        if 'ListOfTags' in selection:
                            instance_tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                            for tag_item in selection['ListOfTags']:
                                if (tag_item['ConditionKey'] in instance_tags and 
                                    instance_tags[tag_item['ConditionKey']] == tag_item.get('ConditionValue')):
                                    has_backup = True
                                    break
                                
                except Exception as e:
                    logger.warning(f"Error checking backup selections for plan {plan['BackupPlanId']}: {str(e)}")
                    continue
                
                if has_backup:
                    break

        except Exception as e:
            logger.error(f"Error listing backup plans: {str(e)}")
            return None

        if not has_backup:
            return {
                'service': 'EC2',
                'resource': instance['InstanceId'],
                'message': "백업 정책 구성이 필요합니다.",
                'severity': '높음',
                'problem': "정기적인 백업 정책이 설정되어 있지 않습니다.",
                'impact': "데이터 손실 위험에 노출되어 있습니다.",
                'benefit': "정기적인 백업으로 데이터 보호 및 신속한 복구가 가능합니다.",
                'steps': [
                    "AWS Backup 정책을 설정합니다.",
                    "스냅샷 생성을 자동화합니다.",
                    "백업 보존 기간을 설정합니다.",
                    "복구 시점 목표(RPO)를 설정하고 검토합니다."
                ]
            }
        return None
        
    except Exception as e:
        logger.error(f"Error in check_backup_recommendations: {str(e)}")
        return None