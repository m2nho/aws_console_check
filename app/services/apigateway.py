import boto3

def get_apigateway_data(aws_access_key, aws_secret_key, region):
    """API Gateway 데이터 수집"""
    try:
        apigateway_client = boto3.client(
            'apigateway',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        response = apigateway_client.get_rest_apis()
        apis = []
        
        for api in response['items']:
            # 스테이지 정보 가져오기
            stages_response = apigateway_client.get_stages(restApiId=api['id'])
            
            apis.append({
                'id': api['id'],
                'name': api['name'],
                'description': api.get('description', 'No description'),
                'created_date': api['createdDate'].strftime('%Y-%m-%d'),
                'stages': len(stages_response.get('item', [])),
                'api_key_required': api.get('apiKeyRequired', False)
            })
        
        return {'apis': apis}
    except Exception as e:
        return {'error': str(e)}

def get_apigateway_recommendations(apis):
    """API Gateway 추천 사항 수집"""
    recommendations = []
    
    for api in apis:
        if not api['api_key_required']:
            recommendations.append({
                'service': 'API Gateway',
                'resource': api['name'],
                'severity': '중간',
                'message': f"API에 API 키가 필요하지 않습니다. 보안을 강화하기 위해 API 키 요구 사항을 고려하세요.",
                'problem': f"API Gateway {api['name']}에 API 키가 필요하지 않아 보안이 취약할 수 있습니다.",
                'impact': "API 키가 없으면 누구나 API에 접근할 수 있어 무단 사용, 과도한 사용 또는 DoS 공격에 취약할 수 있습니다.",
                'steps': [
                    "AWS 콘솔에서 API Gateway 서비스로 이동합니다.",
                    f"API {api['name']}를 선택합니다.",
                    "리소스 섹션에서 메서드를 선택합니다.",
                    "메서드 요청을 편집하고 'API 키 필요' 옵션을 활성화합니다.",
                    "API 키를 생성하고 사용량 계획을 설정합니다.",
                    "API를 다시 배포합니다."
                ],
                'benefit': "API 키를 요구하면 API 사용을 추적하고, 제한하고, 무단 접근을 방지할 수 있습니다.",
                'links': [
                    {'url': 'https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-setup-api-key-with-console.html', 'title': 'API Gateway API 키 설정'},
                    {'url': 'https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-create-usage-plans.html', 'title': 'API Gateway 사용량 계획 생성'}
                ]
            })
    
    return recommendations