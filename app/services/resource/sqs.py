import boto3

def get_sqs_data(aws_access_key, aws_secret_key, region):
    """SQS 대기열 데이터 수집"""
    try:
        sqs_client = boto3.client(
            'sqs',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        response = sqs_client.list_queues()
        queues = []
        
        for queue_url in response.get('QueueUrls', []):
            queue_name = queue_url.split('/')[-1]
            
            # 대기열 속성 가져오기
            attributes = sqs_client.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=['All']
            )['Attributes']
            
            queues.append({
                'name': queue_name,
                'url': queue_url,
                'messages': int(attributes.get('ApproximateNumberOfMessages', 0)),
                'messages_delayed': int(attributes.get('ApproximateNumberOfMessagesDelayed', 0)),
                'messages_not_visible': int(attributes.get('ApproximateNumberOfMessagesNotVisible', 0)),
                'is_fifo': queue_name.endswith('.fifo')
            })
        
        return {'queues': queues}
    except Exception as e:
        return {'error': str(e)}
