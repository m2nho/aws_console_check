import boto3


def get_sqs_recommendations(queues):
    """SQS 대기열 추천 사항 수집"""
    recommendations = []
    
    for queue in queues:
        if queue['messages'] > 1000:
            recommendations.append({
                'service': 'SQS',
                'resource': queue['name'],
                'severity': '중간',
                'message': f"대기열에 많은 메시지({queue['messages']}개)가 있습니다. 소비자 확장을 고려하세요.",
                'problem': f"SQS 대기열 {queue['name']}에 {queue['messages']}개의 메시지가 쌓여 있습니다.",
                'impact': "메시지가 많이 쌓이면 처리 지연이 발생하고 시스템 성능에 영향을 줄 수 있습니다.",
                'steps': [
                    "소비자 애플리케이션의 처리 속도를 확인합니다.",
                    "소비자 인스턴스 수를 늘리는 것을 고려합니다.",
                    "Auto Scaling 그룹을 설정하여 대기열 깊이에 따라 소비자를 자동으로 확장합니다.",
                    "메시지 처리 로직을 최적화합니다."
                ],
                'benefit': "소비자를 확장하면 메시지 처리 속도가 향상되고 시스템 응답성이 개선됩니다.",
                'links': [
                    {'url': 'https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-using-sqs-queue.html', 'title': 'SQS 대기열 기반 Auto Scaling'},
                    {'url': 'https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-best-practices.html', 'title': 'SQS 모범 사례'}
                ]
            })
        if queue['messages_not_visible'] > 100:
            recommendations.append({
                'service': 'SQS',
                'resource': queue['name'],
                'severity': '높음',
                'message': f"처리 중인 메시지가 많습니다. 데드레터 큐 설정을 확인하세요.",
                'problem': f"SQS 대기열 {queue['name']}에 {queue['messages_not_visible']}개의 메시지가 처리 중(비표시) 상태입니다.",
                'impact': "많은 메시지가 처리 중 상태로 유지되면 처리 실패 또는 소비자 문제를 나타낼 수 있습니다.",
                'steps': [
                    "소비자 애플리케이션의 오류 로그를 확인합니다.",
                    "메시지 가시성 타임아웃 설정을 검토합니다.",
                    "데드레터 큐를 설정하여 반복적으로 실패하는 메시지를 캡처합니다.",
                    "소비자 애플리케이션의 메시지 처리 로직을 디버깅합니다."
                ],
                'benefit': "데드레터 큐를 설정하면 문제가 있는 메시지를 격리하고 나머지 메시지 처리를 계속할 수 있습니다.",
                'links': [
                    {'url': 'https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html', 'title': 'SQS 데드레터 큐 사용'},
                    {'url': 'https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html', 'title': 'SQS 가시성 타임아웃 이해'}
                ]
            })
    
    return recommendations