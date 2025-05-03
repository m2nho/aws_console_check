import boto3
from datetime import datetime, timezone

def get_cloudwatch_data(aws_access_key, aws_secret_key, region):
    """CloudWatch 상세 데이터 수집"""
    try:
        cloudwatch_client = boto3.client(
            'cloudwatch',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        # 기본 경보 정보 수집
        alarm_response = cloudwatch_client.describe_alarms()
        alarms = []
        if 'MetricAlarms' in alarm_response:
            for alarm in alarm_response['MetricAlarms']:
                alarm_info = {
                    'name': alarm.get('AlarmName', ''),
                    'state': alarm.get('StateValue', ''),
                    'metric': alarm.get('MetricName', ''),
                    'namespace': alarm.get('Namespace', ''),
                    'statistic': alarm.get('Statistic', ''),
                    'period': alarm.get('Period', 0),
                    'evaluation_periods': alarm.get('EvaluationPeriods', 0),
                    'threshold': alarm.get('Threshold', 0),
                    'comparison_operator': alarm.get('ComparisonOperator', ''),
                    'actions_enabled': alarm.get('ActionsEnabled', False),
                    'alarm_actions': alarm.get('AlarmActions', []),
                    'insufficient_data_actions': alarm.get('InsufficientDataActions', []),
                    'ok_actions': alarm.get('OKActions', [])
                }
                alarms.append(alarm_info)
        
        # 메트릭 정보 수집
        metrics_response = cloudwatch_client.list_metrics()
        metrics = []
        if 'Metrics' in metrics_response:
            for metric in metrics_response['Metrics']:
                metric_info = {
                    'namespace': metric.get('Namespace', ''),
                    'metric_name': metric.get('MetricName', ''),
                    'dimensions': metric.get('Dimensions', [])
                }
                metrics.append(metric_info)
        
        # 대시보드 정보 수집
        dashboards_response = cloudwatch_client.list_dashboards()
        dashboards = dashboards_response.get('DashboardEntries', [])
        
        return {
            'alarms': alarms,
            'metrics': metrics,
            'dashboards': dashboards
        }
    except Exception as e:
        return {'error': str(e)}
