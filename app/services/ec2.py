import boto3
from datetime import datetime, timedelta
from typing import Dict, List, Any
import pytz
import logging

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
                    'InstanceId': instance['InstanceId'],
                    'InstanceType': instance['InstanceType'],
                    'State': instance['State']['Name'],
                    'AvailabilityZone': instance['Placement']['AvailabilityZone'],
                    'LaunchTime': instance.get('LaunchTime'),
                    'StateTransitionTime': None,
                    'SecurityGroups': [],
                    'Tags': instance.get('Tags', []),
                    'CpuMetrics': [],
                    'NetworkMetrics': {},
                    'Volumes': []
                }

                # 보안 그룹 정보 수집
                logger.debug(f"Collecting security group info for {instance['InstanceId']}")
                for sg in instance.get('SecurityGroups', []):
                    try:
                        sg_details = ec2_client.describe_security_groups(GroupIds=[sg['GroupId']])
                        if sg_details['SecurityGroups']:
                            sg_info = {
                                'GroupId': sg['GroupId'],
                                'IpRanges': [],
                                'Ports': []
                            }
                            
                            for rule in sg_details['SecurityGroups'][0]['IpPermissions']:
                                for ip_range in rule.get('IpRanges', []):
                                    sg_info['IpRanges'].append(ip_range.get('CidrIp'))
                                
                                if 'FromPort' in rule:
                                    sg_info['Ports'].append(rule['FromPort'])
                            
                            instance_data['SecurityGroups'].append(sg_info)
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
                            instance_data['StateTransitionTime'] = current_time - timedelta(
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
                        
                        instance_data['CpuMetrics'] = [
                            point['Average'] for point in cpu_metrics['Datapoints']
                        ]
                    except Exception as e:
                        logger.error(f"Error collecting CPU metrics: {str(e)}")

                # 네트워크 메트릭 수집
                if instance['State']['Name'] == 'running':
                    logger.debug(f"Collecting network metrics for {instance['InstanceId']}")
                    try:
                        instance_data['NetworkMetrics'] = _get_network_metrics(
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
                    instance_data['Volumes'] = volumes.get('Volumes', [])
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

def _get_network_metrics(cloudwatch, instance_id: str, current_time: datetime) -> Dict:
    """네트워크 메트릭 수집"""
    metrics = {}
    metric_names = ['NetworkIn', 'NetworkOut', 'NetworkPacketsIn', 'NetworkPacketsOut']
    
    try:
        for metric_name in metric_names:
            response = cloudwatch.get_metric_statistics(
                Namespace='AWS/EC2',
                MetricName=metric_name,
                Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                StartTime=current_time - timedelta(hours=1),
                EndTime=current_time,
                Period=300,
                Statistics=['Average']
            )
            if response['Datapoints']:
                metrics[metric_name] = max(point['Average'] for point in response['Datapoints'])
            else:
                metrics[metric_name] = 0
    except Exception as e:
        logger.error(f"Error collecting network metric {metric_name}: {str(e)}")
        metrics[metric_name] = 0

    return metrics

def get_ec2_recommendations(instances: Dict) -> List[Dict]:
    """EC2 인스턴스 추천 사항 수집"""
    logger.info("Starting EC2 recommendations analysis")
    try:
        recommendations = []

        if not instances:
            logger.warning("No instances data found")
            return []

        # instances가 리스트인 경우
        if isinstance(instances, list):
            instance_list = instances
        # instances가 딕셔너리이고 'instances' 키가 있는 경우
        elif isinstance(instances, dict) and 'instances' in instances:
            instance_list = instances['instances']
        # instances가 딕셔너리이지만 'instances' 키가 없는 경우
        elif isinstance(instances, dict):
            instance_list = [instances]
        else:
            logger.error(f"Unexpected data type: {type(instances)}")
            return []

        logger.info(f"Processing {len(instance_list)} instances")

        for instance in instance_list:
            instance_id = instance.get('InstanceId', 'unknown')
            logger.debug(f"Processing instance: {instance_id}")

            try:
                # 1. 장기 중지된 인스턴스 검사
                if instance.get('State') == 'stopped':
                    stopped_instance_rec = check_stopped_instance(instance)
                    if stopped_instance_rec:
                        recommendations.append(stopped_instance_rec)

                # 2. 이전 세대 인스턴스 타입 검사
                if instance.get('InstanceType'):
                    old_gen_rec = check_old_generation_instance(instance)
                    if old_gen_rec:
                        recommendations.append(old_gen_rec)

                # 3. 예약 인스턴스 추천
                if instance.get('State') == 'running':
                    ri_rec = check_reserved_instance_recommendation(instance)
                    if ri_rec:
                        recommendations.append(ri_rec)

                # 4. 보안 그룹 검사
                if instance.get('SecurityGroups'):
                    security_rec = check_security_group_recommendations(instance)
                    if security_rec:
                        recommendations.append(security_rec)

                # 5. CPU 사용률 모니터링
                if instance.get('State') == 'running' and instance.get('CpuMetrics'):
                    cpu_rec = check_cpu_utilization(instance)
                    if cpu_rec:
                        recommendations.append(cpu_rec)

                # 6. EBS 볼륨 최적화
                if instance.get('Volumes'):
                    ebs_rec = check_ebs_optimization(instance)
                    if ebs_rec:
                        recommendations.append(ebs_rec)

                # 7. 태그 관리
                if 'Tags' in instance:
                    tag_rec = check_tag_recommendations(instance)
                    if tag_rec:
                        recommendations.append(tag_rec)

                # 8. 네트워크 성능 모니터링
                if instance.get('NetworkMetrics'):
                    network_rec = check_network_performance(instance)
                    if network_rec:
                        recommendations.append(network_rec)

                # 9. 백업 정책 검사
                if instance.get('InstanceId'):
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

def check_stopped_instance(instance: Dict) -> Dict:
    """장기 중지된 인스턴스 검사"""
    instance_id = instance.get('InstanceId', 'unknown')
    logger.debug(f"Checking stopped instance: {instance_id}")
    
    try:
        if instance.get('State') == 'stopped':
            stop_duration = _calculate_stop_duration(instance.get('StateTransitionTime'))
            if stop_duration and stop_duration.days >= 7:
                logger.info(f"Found long-stopped instance: {instance_id}")
                return {
                    'service': 'EC2',
                    'resource': instance_id,
                    'message': f"장기 중지된 인스턴스의 검토가 필요합니다.",
                    'severity': '중간',
                    'problem': f"EC2 인스턴스가 {stop_duration.days}일 동안 중지된 상태입니다.",
                    'impact': "스토리지 비용이 지속적으로 발생하고 있습니다.",
                    'benefit': "불필요한 인스턴스 정리를 통한 비용 절감이 가능합니다.",
                    'steps': [
                        "AWS 콘솔에서 EC2 서비스로 이동합니다.",
                        f"인스턴스 {instance_id}를 선택합니다.",
                        "필요하지 않은 경우 '인스턴스 종료' 작업을 수행합니다.",
                        "필요한 경우 AMI를 생성하여 나중에 복원할 수 있도록 합니다."
                    ]
                }
        return None
    except Exception as e:
        logger.error(f"Error in check_stopped_instance for {instance_id}: {str(e)}")
        return None

def check_old_generation_instance(instance: Dict) -> Dict:
    """이전 세대 인스턴스 타입 검사"""
    instance_id = instance.get('InstanceId', 'unknown')
    instance_type = instance.get('InstanceType', '')
    logger.debug(f"Checking instance type for {instance_id}: {instance_type}")
    
    try:
        if instance_type.startswith(('t2.', 'm4.', 'c4.', 'r4.')):
            new_generation = _get_new_generation_equivalent(instance_type)
            logger.info(f"Found old generation instance: {instance_id} ({instance_type})")
            return {
                'service': 'EC2',
                'resource': instance_id,
                'message': f"이전 세대 인스턴스 타입({instance_type})의 업그레이드가 필요합니다.",
                'severity': '낮음',
                'problem': f"이전 세대 인스턴스 타입({instance_type})을 사용하고 있습니다.",
                'impact': f"최신 세대 인스턴스({new_generation}) 대비 성능 및 비용 효율성이 낮은 상태입니다.",
                'benefit': "최신 세대 인스턴스 사용으로 성능 향상 및 비용 효율성 개선이 가능합니다.",
                'steps': [
                    "워크로드 패턴을 분석합니다.",
                    f"인스턴스 타입을 {new_generation}으로 변경합니다.",
                    "변경 후 워크로드를 모니터링합니다."
                ]
            }
        return None
    except Exception as e:
        logger.error(f"Error in check_old_generation_instance for {instance_id}: {str(e)}")
        return None

def check_reserved_instance_recommendation(instance: Dict) -> Dict:
    """예약 인스턴스 추천"""
    try:
        logger.debug(f"Checking reserved instance recommendation for instance {instance.get('InstanceId')}")
        if instance['State'] == 'running':
            runtime = _calculate_runtime(instance.get('LaunchTime'))
            if runtime and runtime.days >= 30:
                logger.info(f"Instance {instance['InstanceId']} has been running for {runtime.days} days. Recommending reserved instance.")
                return {
                    'service': 'EC2',
                    'resource': instance['InstanceId'],
                    'message': f"{runtime.days}일 동안 실행 중인 인스턴스의 예약 인스턴스 전환이 필요합니다.",
                    'severity': '중간',
                    'problem': f"온디맨드 인스턴스가 {runtime.days}일 동안 지속 실행 중입니다.",
                    'impact': "온디맨드 요금으로 인한 추가 비용이 발생하고 있습니다.",
                    'benefit': "예약 인스턴스 적용으로 최대 72%까지 비용 절감이 가능합니다.",
                    'steps': [
                        "인스턴스의 사용 패턴을 분석합니다.",
                        "적절한 예약 기간과 선결제 옵션을 선택합니다.",
                        "예약 인스턴스를 구매합니다."
                    ]
                }
        logger.debug(f"No reserved instance recommendation for instance {instance.get('InstanceId')}")
        return None
    except Exception as e:
        logger.error(f"Error in check_reserved_instance_recommendation for instance {instance.get('InstanceId')}: {str(e)}", exc_info=True)
        return None
    
def check_security_group_recommendations(instance: Dict) -> Dict:
    """보안 그룹 검사"""
    try:
        logger.debug(f"Checking security group recommendations for instance {instance.get('InstanceId')}")
        security_issues = []
        for sg in instance.get('SecurityGroups', []):
            # 전체 개방된 포트 검사
            logger.debug(f"Analyzing security group {sg.get('GroupId')}")
            if '0.0.0.0/0' in sg.get('IpRanges', []):
                msg = f"보안 그룹 {sg['GroupId']}에 전체 개방된 규칙이 있습니다."
                logger.warning(msg)
                security_issues.append(f"보안 그룹 {sg['GroupId']}에 전체 개방된 규칙이 있습니다.")
            
            # 위험 포트 검사
            dangerous_ports = {22, 3389, 21, 23, 445}
            for port in sg.get('Ports', []):
                if port in dangerous_ports:
                    security_issues.append(f"보안 그룹 {sg['GroupId']}에 위험 포트({port})가 개방되어 있습니다.")

        if security_issues:
            logger.info(f"Found {len(security_issues)} security issues for instance {instance['InstanceId']}")
            return {
                'service': 'EC2',
                'resource': instance['InstanceId'],
                'message': "보안 그룹 구성 개선이 필요합니다.",
                'severity': '높음',
                'problem': "\n".join(security_issues),
                'impact': "무분별한 접근 허용으로 인한 보안 위험이 있습니다.",
                'benefit': "보안 태세 강화 및 잠재적 위험 감소가 가능합니다.",
                'steps': [
                    "전체 개방된 규칙을 필요한 IP 범위로 제한합니다.",
                    "위험 포트에 대한 접근을 제한합니다.",
                    "불필요한 규칙을 제거합니다.",
                    "정기적인 보안 그룹 규칙 검토를 수행합니다."
                ]
            }
        logger.debug(f"No security issues found for instance {instance['InstanceId']}")
        return None
    except Exception as e:
        logger.error(f"Error in check_security_group_recommendations for instance {instance.get('InstanceId')}: {str(e)}", exc_info=True)
        return None

def check_cpu_utilization(instance: Dict) -> Dict:
    """CPU 사용률 모니터링
    
    CPU 사용률 패턴을 분석하여 다음과 같은 상태를 확인합니다:
    - 매우 낮음 (20% 미만)
    - 적정 (20-80%)
    - 높음 (80% 이상)
    """
    # 상수 정의
    CPU_THRESHOLD = {
        'VERY_LOW': 20,
        'HIGH': 80,
        'MONITORING_DAYS': 7
    }

    try:
        instance_id = instance.get('InstanceId')
        logger.debug(f"Checking CPU utilization for instance {instance_id}")

        if not (instance['State'] == 'running' and instance.get('CpuMetrics')):
            logger.debug(f"Instance {instance_id} is not running or has no CPU metrics")
            return None

        cpu_stats = _analyze_cpu_metrics(instance['CpuMetrics'])
        logger.debug(f"CPU stats for instance {instance_id}: {cpu_stats}")

        # CPU 사용 패턴 분석
        def get_cpu_pattern() -> Dict:
            if cpu_stats['low_usage_days'] >= CPU_THRESHOLD['MONITORING_DAYS']:
                return {
                    'pattern': 'under_utilized',
                    'days': cpu_stats['low_usage_days'],
                    'threshold': CPU_THRESHOLD['VERY_LOW'],
                    'recommendation': {
                        'message': f"CPU 사용률이 {cpu_stats['low_usage_days']}일 연속 {CPU_THRESHOLD['VERY_LOW']}% 미만으로 유지되고 있습니다.",
                        'severity': '중간',
                        'steps': [
                            "CloudWatch 메트릭을 검토합니다.",
                            "인스턴스 다운사이징을 검토합니다.",
                            "예약 인스턴스 전환을 검토합니다.",
                            "자동 중지/시작 스케줄링을 고려합니다."
                        ],
                        'problem': "지속적으로 낮은 CPU 사용률이 발생하고 있습니다.",
                        'impact': "과다 프로비저닝으로 인한 불필요한 비용이 발생하고 있습니다.",
                        'benefit': "적절한 크기 조정으로 최대 30-50% 비용 절감이 가능합니다."
                    }
                }
            elif cpu_stats['high_usage_days'] >= CPU_THRESHOLD['MONITORING_DAYS']:
                return {
                    'pattern': 'over_utilized',
                    'days': cpu_stats['high_usage_days'],
                    'threshold': CPU_THRESHOLD['HIGH'],
                    'recommendation': {
                        'message': f"CPU 사용률이 {cpu_stats['high_usage_days']}일 연속 {CPU_THRESHOLD['HIGH']}% 이상으로 유지되고 있습니다.",
                        'severity': '높음',
                        'steps': [
                            "CloudWatch 메트릭을 상세 분석합니다.",
                            "인스턴스 업스케일링을 검토합니다.",
                            "Auto Scaling 구성을 검토합니다.",
                            "워크로드 분산 방안을 검토합니다."
                        ],
                        'problem': "지속적으로 높은 CPU 사용률이 발생하고 있습니다.",
                        'impact': "성능 병목 현상으로 서비스 지연이 발생할 수 있습니다.",
                        'benefit': "적절한 리소스 확장으로 안정적인 서비스 제공이 가능합니다."
                    }
                }
            return None

        cpu_pattern = get_cpu_pattern()
        if not cpu_pattern:
            logger.debug(f"No significant CPU utilization pattern found for instance {instance_id}")
            return None

        # 결과 반환
        return {
            'service': 'EC2',
            'resource': instance_id,
            'message': cpu_pattern['recommendation']['message'],
            'severity': cpu_pattern['recommendation']['severity'],
            'steps': cpu_pattern['recommendation']['steps'],
            'problem': cpu_pattern['recommendation']['problem'],
            'impact': cpu_pattern['recommendation']['impact'],
            'benefit': cpu_pattern['recommendation']['benefit'],
            'metadata': {
                'pattern': cpu_pattern['pattern'],
                'days': cpu_pattern['days'],
                'threshold': cpu_pattern['threshold']
            }
        }

    except Exception as e:
        logger.error(f"Error in check_cpu_utilization for instance {instance_id}: {str(e)}", exc_info=True)
        return None


def check_ebs_optimization(instance: Dict) -> Dict:
    """EBS 볼륨 최적화 검사"""
    try:
        logger.debug(f"Checking EBS optimization for instance {instance.get('InstanceId')}")
        issues = []
        for volume in instance.get('Volumes', []):
            logger.debug(f"Analyzing volume {volume.get('VolumeId')} for instance {instance.get('InstanceId')}")
            
            # 미사용 볼륨 검사
            if not volume.get('Attachments'):
                msg = f"미사용 EBS 볼륨 발견: {volume['VolumeId']}"
                logger.warning(msg)
                issues.append(msg)
            
            # IOPS 과다 설정 검사
            if volume.get('Iops') and volume.get('VolumeType') in ['io1', 'io2']:
                if volume['Iops'] > 10000:
                    msg = f"과다 설정된 IOPS 발견: {volume['VolumeId']}"
                    logger.warning(msg)
                    issues.append(msg)
            
            # gp2에서 gp3로 마이그레이션 추천
            if volume.get('VolumeType') == 'gp2':
                msg = f"gp3로 마이그레이션 권장: {volume['VolumeId']}"
                logger.info(msg)
                issues.append(msg)

        if issues:
            logger.info(f"Found {len(issues)} EBS issues for instance {instance['InstanceId']}")
            return {
                'service': 'EC2',
                'resource': instance['InstanceId'],
                'message': "EBS 볼륨 최적화가 필요합니다.",
                'severity': '중간',
                'steps': [
                    "미사용 볼륨 식별 및 제거",
                    "볼륨 크기 및 IOPS 최적화",
                    "gp2에서 gp3로 마이그레이션 검토",
                    "주기적인 스냅샷 정책 검토"
                ],
                'problem': "\n".join(issues),
                'impact': "불필요한 스토리지 비용 발생",
                'benefit': "스토리지 비용 최적화 및 성능 개선"
            }
        logger.debug(f"No EBS optimization issues found for instance {instance['InstanceId']}")
        return None
    except Exception as e:
        logger.error(f"Error in check_ebs_optimization for instance {instance.get('InstanceId')}: {str(e)}", exc_info=True)
        return None

def check_tag_recommendations(instance: Dict) -> Dict:
    """태그 관리 검사"""
    try:
        logger.debug(f"Checking tag recommendations for instance {instance.get('InstanceId')}")
        required_tags = {'Name', 'Environment', 'Owner', 'Project'}
        instance_tags = {tag['Key'] for tag in instance.get('Tags', [])}
        missing_tags = required_tags - instance_tags

        if missing_tags:
            logger.warning(f"Instance {instance['InstanceId']} is missing required tags: {missing_tags}")
            return {
                'service': 'EC2',
                'resource': instance['InstanceId'],
                'message': f"필수 태그 보완이 필요합니다.",
                'severity': '낮음',
                'problem': f"다음 필수 태그가 누락되어 있습니다: {', '.join(missing_tags)}",
                'impact': "리소스 관리 및 비용 추적이 어려운 상태입니다.",
                'benefit': "체계적인 리소스 관리 및 비용 추적이 가능합니다.",
                'steps': [
                    "필수 태그를 정의하고 적용합니다.",
                    "태그 기반 비용 할당을 설정합니다.",
                    "자동 태깅 규칙을 구성합니다.",
                    "정기적인 태그 컴플라이언스를 검토합니다."
                ]
            }
        logger.debug(f"No missing tags found for instance {instance['InstanceId']}")
        return None
    except Exception as e:
        logger.error(f"Error in check_tag_recommendations for instance {instance.get('InstanceId')}: {str(e)}", exc_info=True)
        return None

def check_network_performance(instance: Dict) -> Dict:
    """네트워크 성능 모니터링"""
    try:
        logger.debug(f"Checking network performance for instance {instance.get('InstanceId')}")
        network_metrics = instance.get('NetworkMetrics', {})
        issues = []
        
        # 네트워크 사용량 검사
        if network_metrics.get('NetworkIn', 0) > 100000000:  # 100MB/s
            msg = "높은 인바운드 네트워크 사용량"
            logger.warning(f"Instance {instance['InstanceId']}: {msg}")
            issues.append(msg)
        if network_metrics.get('NetworkOut', 0) > 100000000:  # 100MB/s
            msg = "높은 아웃바운드 네트워크 사용량"
            logger.warning(f"Instance {instance['InstanceId']}: {msg}")
            issues.append(msg)

        if issues:
            logger.info(f"Found {len(issues)} network performance issues for instance {instance['InstanceId']}")
            return {
                'service': 'EC2',
                'resource': instance['InstanceId'],
                'message': "네트워크 성능 개선이 필요합니다.",
                'severity': '높음',
                'problem': "\n".join(issues),
                'impact': "애플리케이션 성능 저하 및 사용자 경험이 악화되고 있습니다.",
                'benefit': "네트워크 최적화로 성능 및 안정성 개선이 가능합니다.",
                'steps': [
                    "네트워크 성능 메트릭을 분석합니다.",
                    "ENI 설정을 최적화합니다.",
                    "네트워크 ACL 및 라우팅 테이블을 검토합니다.",
                    "향상된 네트워킹 활성화를 검토합니다."
                ]
            }
        logger.debug(f"No network performance issues found for instance {instance['InstanceId']}")
        return None
    except Exception as e:
        logger.error(f"Error in check_network_performance for instance {instance.get('InstanceId')}: {str(e)}", exc_info=True)
        return None

def check_backup_recommendations(instance: Dict) -> Dict:
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

# 헬퍼 함수들
def _calculate_stop_duration(stop_time):
    """중지 기간 계산"""
    if not stop_time:
        return None
    return datetime.now(pytz.UTC) - stop_time

def _calculate_runtime(launch_time):
    """실행 기간 계산"""
    if not launch_time:
        return None
    return datetime.now(pytz.UTC) - launch_time

def _get_new_generation_equivalent(instance_type):
    """새로운 세대 인스턴스 타입 매핑"""
    mapping = {
        't2.': 't3.',
        'm4.': 'm5.',
        'c4.': 'c5.',
        'r4.': 'r5.'
    }
    for old, new in mapping.items():
        if instance_type.startswith(old):
            return instance_type.replace(old, new)
    return instance_type

def _analyze_cpu_metrics(metrics):
    """CPU 메트릭 분석"""
    try:
        logger.debug(f"Analyzing CPU metrics with {len(metrics)} data points")
        low_usage_days = 0
        high_usage_days = 0
        
        for metric in metrics:
            if metric < 20:
                low_usage_days += 1/24
            elif metric > 80:
                high_usage_days += 1/24

        result = {
            'low_usage_days': int(low_usage_days),
            'high_usage_days': int(high_usage_days)
        }
        logger.debug(f"CPU analysis result: {result}")
        return result
    except Exception as e:
        logger.error(f"Error in _analyze_cpu_metrics: {str(e)}", exc_info=True)
        return {'low_usage_days': 0, 'high_usage_days': 0}