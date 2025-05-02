# app/services/ec2_checks/utils.py
# Helper functions for EC2 recommendation checks

import boto3
from datetime import datetime, timedelta
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

def calculate_stop_duration(stop_time):
    """중지 기간 계산"""
    if not stop_time:
        return None
    return datetime.now(pytz.UTC) - stop_time

def calculate_runtime(launch_time):
    """실행 기간 계산"""
    if not launch_time:
        return None
    return datetime.now(pytz.UTC) - launch_time

def get_new_generation_equivalent(instance_type):
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

def analyze_cpu_metrics(metrics):
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
        logger.error(f"Error in analyze_cpu_metrics: {str(e)}", exc_info=True)
        return {'low_usage_days': 0, 'high_usage_days': 0}

def get_network_metrics(cloudwatch, instance_id, current_time):
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