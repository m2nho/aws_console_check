import boto3

def get_sns_data(aws_access_key, aws_secret_key, region):
    """SNS 주제 데이터 수집"""
    try:
        sns_client = boto3.client(
            'sns',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        response = sns_client.list_topics()
        topics = []
        
        for topic in response['Topics']:
            topic_arn = topic['TopicArn']
            topic_name = topic_arn.split(':')[-1]
            
            # 구독 정보 가져오기
            subscriptions_response = sns_client.list_subscriptions_by_topic(TopicArn=topic_arn)
            subscriptions_count = len(subscriptions_response.get('Subscriptions', []))
            
            # 주제 속성 가져오기
            attributes_response = sns_client.get_topic_attributes(TopicArn=topic_arn)
            
            topics.append({
                'name': topic_name,
                'arn': topic_arn,
                'subscriptions': subscriptions_count,
                'effective_delivery_policy': 'DeliveryPolicy' in attributes_response['Attributes']
            })
        
        return {'topics': topics}
    except Exception as e:
        return {'error': str(e)}
