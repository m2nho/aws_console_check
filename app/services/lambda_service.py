import boto3

def get_lambda_data(aws_access_key, aws_secret_key, region):
    """Lambda 함수 데이터 수집"""
    try:
        lambda_client = boto3.client(
            'lambda',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        response = lambda_client.list_functions()
        functions = []
        for function in response['Functions']:
            functions.append({
                'name': function['FunctionName'],
                'runtime': function['Runtime'],
                'memory': function['MemorySize'],
                'timeout': function['Timeout']
            })
        return {'functions': functions}
    except Exception as e:
        return {'error': str(e)}

def get_lambda_recommendations(functions):
    """Lambda 함수 추천 사항 수집"""
    recommendations = []
    
    for function in functions:
        if function['memory'] > 512:
            recommendations.append({
                'service': 'Lambda',
                'resource': function['name'],
                'severity': '낮음',
                'message': f"Lambda 함수의 메모리가 {function['memory']}MB로 설정되어 있습니다. 필요에 따라 메모리를 줄여 비용을 절감하세요.",
                'problem': f"Lambda 함수 {function['name']}의 메모리가 {function['memory']}MB로 설정되어 있어 필요 이상으로 높을 수 있습니다.",
                'impact': "Lambda 함수에 할당된 메모리가 필요 이상으로 높으면 불필요한 비용이 발생합니다.",
                'steps': [
                    "CloudWatch Logs에서 함수의 실제 메모리 사용량을 확인합니다.",
                    "AWS Lambda 콘솔에서 함수 구성을 편집합니다.",
                    "메모리 할당을 실제 사용량에 맞게 조정합니다.",
                    "변경 후 함수 성능을 모니터링하여 문제가 없는지 확인합니다."
                ],
                'benefit': "Lambda 함수의 메모리 할당을 최적화하면 비용을 절감하면서도 필요한 성능을 유지할 수 있습니다.",
                'links': [
                    {'url': 'https://docs.aws.amazon.com/lambda/latest/dg/configuration-memory.html', 'title': 'Lambda 함수 메모리 구성'},
                    {'url': 'https://aws.amazon.com/blogs/compute/operating-lambda-performance-optimization-part-1/', 'title': 'Lambda 성능 최적화 가이드'}
                ]
            })
        if function['timeout'] > 60:
            recommendations.append({
                'service': 'Lambda',
                'resource': function['name'],
                'severity': '낮음',
                'message': f"Lambda 함수의 타임아웃이 {function['timeout']}초로 설정되어 있습니다. 장시간 실행되는 작업은 다른 서비스를 고려해보세요.",
                'problem': f"Lambda 함수 {function['name']}의 타임아웃이 {function['timeout']}초로 설정되어 있어 장시간 실행되는 작업에 사용되고 있을 수 있습니다.",
                'impact': "Lambda는 단기 실행 작업에 최적화되어 있으며, 장시간 실행되는 작업은 비용이 증가하고 타임아웃 위험이 있습니다.",
                'steps': [
                    "함수의 실행 시간을 CloudWatch Logs에서 확인합니다.",
                    "실행 시간이 길다면 작업을 더 작은 단위로 분할하는 것을 고려합니다.",
                    "장시간 실행되는 작업은 Step Functions, Batch, ECS 등의 서비스로 마이그레이션을 고려합니다.",
                    "함수 코드를 최적화하여 실행 시간을 단축합니다."
                ],
                'benefit': "적절한 서비스를 사용하면 비용을 절감하고, 안정성을 향상시키며, 관리 오버헤드를 줄일 수 있습니다.",
                'links': [
                    {'url': 'https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html', 'title': 'Lambda 모범 사례'},
                    {'url': 'https://aws.amazon.com/step-functions/', 'title': 'AWS Step Functions 소개'}
                ]
            })
    
    return recommendations