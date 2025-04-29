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

def get_sns_recommendations(topics):
    """SNS 주제 추천 사항 수집"""
    recommendations = []
    
    for topic in topics:
        if topic['subscriptions'] == 0:
            recommendations.append({
                'service': 'SNS',
                'resource': topic['name'],
                'severity': '낮음',
                'message': f"SNS 주제에 구독이 없습니다. 필요하지 않다면 삭제를 고려하세요.",
                'problem': f"SNS 주제 {topic['name']}에 구독이 없습니다.",
                'impact': "사용되지 않는 SNS 주제는 관리 오버헤드를 증가시키고 혼란을 야기할 수 있습니다.",
                'steps': [
                    "AWS 콘솔에서 SNS 서비스로 이동합니다.",
                    f"주제 {topic['name']}를 선택합니다.",
                    "주제가 필요한 경우 구독을 추가합니다.",
                    "주제가 필요하지 않은 경우 삭제합니다."
                ],
                'benefit': "불필요한 리소스를 제거하면 AWS 환경이 더 깔끔해지고 관리가 용이해집니다.",
                'links': [
                    {'url': 'https://docs.aws.amazon.com/sns/latest/dg/sns-create-subscribe-endpoint-to-topic.html', 'title': 'SNS 주제에 엔드포인트 구독'},
                    {'url': 'https://docs.aws.amazon.com/sns/latest/dg/sns-delete-topic.html', 'title': 'SNS 주제 삭제'}
                ]
            })
    
    return recommendations