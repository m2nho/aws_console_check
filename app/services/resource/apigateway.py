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
