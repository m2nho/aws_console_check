import boto3
from datetime import datetime, timedelta
from typing import Dict, List, Any
import pytz
import logging

# Import check functions from ec2_checks package
from app.services.ec2_checks import (
    check_stopped_instance,
    check_old_generation_instance,
    check_reserved_instance_recommendation,
    check_security_group_recommendations,
    check_cpu_utilization,
    check_ebs_optimization,
    check_tag_recommendations,
    check_network_performance,
    check_backup_recommendations
)
from app.services.ec2_checks.utils import get_network_metrics

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ec2_recommendations.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def get_ec2_data(aws_access_key: str, aws_secret_key: str, region: str) -> Dict:
    """EC2 인스턴스 데이터 수집"""
    logger.info("Starting EC2 data collection")
    try:
        ec2_client = boto3.client(
            'ec2',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        cloudwatch = boto3.client(
            'cloudwatch',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )

        current_time = datetime.now(pytz.UTC)
        response = ec2_client.describe_instances()
        instances = []
        
        logger.info(f"Found {len(response['Reservations'])} reservations")
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                logger.debug(f"Processing instance {instance['InstanceId']}")
                
                # 기본 인스턴스 정보
                instance_data = {
                    'id': instance['InstanceId'],  # 변경: InstanceId -> id
                    'type': instance['InstanceType'],  # 변경: InstanceType -> type
                    'state': instance['State']['Name'],  # 변경: State -> state
                    'az': instance['Placement']['AvailabilityZone'],  # 변경: AvailabilityZone -> az
                    'launch_time': instance.get('LaunchTime'),
                    'state_transition_time': None,
                    'security_groups': [],
                    'tags': instance.get('Tags', []),
                    'cpu_metrics': [],
                    'network_metrics': {},
                    'volumes': []
                }

                # 보안 그룹 정보 수집
                logger.debug(f"Collecting security group info for {instance['InstanceId']}")
                for sg in instance.get('SecurityGroups', []):
                    try:
                        sg_details = ec2_client.describe_security_groups(GroupIds=[sg['GroupId']])
                        if sg_details['SecurityGroups']:
                            sg_info = {
                                'group_id': sg['GroupId'],
                                'ip_ranges': [],
                                'ports': []
                            }
                            
                            for rule in sg_details['SecurityGroups'][0]['IpPermissions']:
                                for ip_range in rule.get('IpRanges', []):
                                    sg_info['ip_ranges'].append(ip_range.get('CidrIp'))
                                
                                if 'FromPort' in rule:
                                    sg_info['ports'].append(rule['FromPort'])
                            
                            instance_data['security_groups'].append(sg_info)
                    except Exception as e:
                        logger.error(f"Error collecting security group info: {str(e)}")

                # 상태 변경 시간 수집
                if instance['State']['Name'] == 'stopped':
                    logger.debug(f"Collecting state transition time for stopped instance {instance['InstanceId']}")
                    try:
                        status_checks = cloudwatch.get_metric_data(
                            MetricDataQueries=[{
                                'Id': 'status',
                                'MetricStat': {
                                    'Metric': {
                                        'Namespace': 'AWS/EC2',
                                        'MetricName': 'StatusCheckFailed',
                                        'Dimensions': [{'Name': 'InstanceId', 'Value': instance['InstanceId']}]
                                    },
                                    'Period': 3600,
                                    'Stat': 'Maximum'
                                },
                                'ReturnData': True
                            }],
                            StartTime=current_time - timedelta(days=30),
                            EndTime=current_time
                        )
                        
                        if status_checks['MetricDataResults'][0]['Values']:
                            instance_data['state_transition_time'] = current_time - timedelta(
                                hours=len(status_checks['MetricDataResults'][0]['Values'])
                            )
                    except Exception as e:
                        logger.error(f"Error collecting status checks: {str(e)}")

                # CPU 사용률 데이터 수집
                if instance['State']['Name'] == 'running':
                    logger.debug(f"Collecting CPU metrics for {instance['InstanceId']}")
                    try:
                        cpu_metrics = cloudwatch.get_metric_statistics(
                            Namespace='AWS/EC2',
                            MetricName='CPUUtilization',
                            Dimensions=[{'Name': 'InstanceId', 'Value': instance['InstanceId']}],
                            StartTime=current_time - timedelta(days=7),
                            EndTime=current_time,
                            Period=3600,
                            Statistics=['Average']
                        )
                        
                        instance_data['cpu_metrics'] = [
                            point['Average'] for point in cpu_metrics['Datapoints']
                        ]
                    except Exception as e:
                        logger.error(f"Error collecting CPU metrics: {str(e)}")

                # 네트워크 메트릭 수집
                if instance['State']['Name'] == 'running':
                    logger.debug(f"Collecting network metrics for {instance['InstanceId']}")
                    try:
                        instance_data['network_metrics'] = get_network_metrics(
                            cloudwatch, 
                            instance['InstanceId'], 
                            current_time
                        )
                    except Exception as e:
                        logger.error(f"Error collecting network metrics: {str(e)}")

                # EBS 볼륨 정보 수집
                logger.debug(f"Collecting volume information for {instance['InstanceId']}")
                try:
                    volumes = ec2_client.describe_volumes(
                        Filters=[{'Name': 'attachment.instance-id', 'Values': [instance['InstanceId']]}]
                    )
                    instance_data['volumes'] = volumes.get('Volumes', [])
                except Exception as e:
                    logger.error(f"Error collecting volume information: {str(e)}")

                instances.append(instance_data)
                logger.info(f"Successfully collected data for instance {instance['InstanceId']}")

        result = {'instances': instances}
        logger.info(f"Successfully collected data for {len(instances)} instances")
        return result
    except Exception as e:
        logger.error(f"Error in get_ec2_data: {str(e)}")
        return {'error': str(e)}

def get_ec2_recommendations(instances: List[Dict]) -> List[Dict]:
    """EC2 인스턴스 추천 사항 수집"""
    logger.info("Starting EC2 recommendations analysis")
    try:
        recommendations = []

        # 데이터 구조 확인 및 로깅
        logger.info(f"Received data type: {type(instances)}")
        logger.debug(f"Instances data: {instances}")
        
        # instances가 이미 리스트 형태로 전달됨
        instance_list = instances
        logger.info(f"Processing {len(instance_list)} instances")

        for instance in instance_list:
            instance_id = instance.get('id', 'unknown')  # InstanceId -> id
            logger.debug(f"Processing instance: {instance_id}")

            try:
                # 1. 장기 중지된 인스턴스 검사
                if instance.get('state') == 'stopped':  # State -> state
                    stopped_instance_rec = check_stopped_instance(instance)
                    if stopped_instance_rec:
                        recommendations.append(stopped_instance_rec)

                # 2. 이전 세대 인스턴스 타입 검사
                if instance.get('type'):  # InstanceType -> type
                    old_gen_rec = check_old_generation_instance(instance)
                    if old_gen_rec:
                        recommendations.append(old_gen_rec)

                # 3. 예약 인스턴스 추천
                if instance.get('state') == 'running':  # State -> state
                    ri_rec = check_reserved_instance_recommendation(instance)
                    if ri_rec:
                        recommendations.append(ri_rec)

                # 4. 보안 그룹 검사
                if instance.get('security_groups'):  # SecurityGroups -> security_groups
                    security_rec = check_security_group_recommendations(instance)
                    if security_rec:
                        recommendations.append(security_rec)

                # 5. CPU 사용률 모니터링
                if instance.get('state') == 'running' and instance.get('cpu_metrics'):  # CpuMetrics -> cpu_metrics
                    cpu_rec = check_cpu_utilization(instance)
                    if cpu_rec:
                        recommendations.append(cpu_rec)

                # 6. EBS 볼륨 최적화
                if instance.get('volumes'):  # Volumes -> volumes
                    ebs_rec = check_ebs_optimization(instance)
                    if ebs_rec:
                        recommendations.append(ebs_rec)

                # 7. 태그 관리
                if instance.get('tags'):  # Tags -> tags
                    tag_rec = check_tag_recommendations(instance)
                    if tag_rec:
                        recommendations.append(tag_rec)

                # 8. 네트워크 성능 모니터링
                if instance.get('network_metrics'):  # NetworkMetrics -> network_metrics
                    network_rec = check_network_performance(instance)
                    if network_rec:
                        recommendations.append(network_rec)

                # 9. 백업 정책 검사
                if instance.get('id'):  # InstanceId -> id
                    backup_rec = check_backup_recommendations(instance)
                    if backup_rec:
                        recommendations.append(backup_rec)

            except Exception as e:
                logger.error(f"Error processing instance {instance_id}: {str(e)}")
                continue

        logger.info(f"Found {len(recommendations)} recommendations")
        return recommendations
        
    except Exception as e:
        logger.error(f"Error in get_ec2_recommendations: {str(e)}")
        return []
