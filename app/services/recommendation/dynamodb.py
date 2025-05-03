import boto3

def get_dynamodb_recommendations(tables):
    """DynamoDB 테이블 추천 사항 수집"""
    recommendations = []
    
    for table in tables:
        if table['items'] > 1000000:  # 100만 항목 이상
            recommendations.append({
                'service': 'DynamoDB',
                'resource': table['name'],
                'severity': '중간',
                'message': f"테이블에 많은 항목이 있습니다. 파티셔닝 전략을 검토하세요.",
                'problem': f"DynamoDB 테이블 {table['name']}에 {table['items']}개의 항목이 있어 성능에 영향을 줄 수 있습니다.",
                'impact': "항목이 많은 테이블은 쿼리 성능이 저하되고 처리량 비용이 증가할 수 있습니다.",
                'steps': [
                    "테이블의 액세스 패턴을 분석합니다.",
                    "파티셔닝 키 선택을 검토합니다.",
                    "필요한 경우 테이블을 여러 개로 분할하는 것을 고려합니다.",
                    "글로벌 보조 인덱스 사용을 최적화합니다."
                ],
                'benefit': "효과적인 파티셔닝 전략은 쿼리 성능을 향상시키고 비용을 절감할 수 있습니다.",
                'links': [
                    {'url': 'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/bp-partition-key-design.html', 'title': 'DynamoDB 파티션 키 설계 모범 사례'},
                    {'url': 'https://aws.amazon.com/blogs/database/choosing-the-right-dynamodb-partition-key/', 'title': '올바른 DynamoDB 파티션 키 선택하기'}
                ]
            })
    
    # 테이블이 없는 경우에도 기본 추천 사항 추가
    if not tables:
        recommendations.append({
            'service': 'DynamoDB',
            'resource': 'All',
            'severity': '낮음',
            'message': "DynamoDB 테이블이 없습니다. 필요한 경우 테이블을 생성하세요.",
            'problem': "현재 계정에 DynamoDB 테이블이 없습니다.",
            'impact': "NoSQL 데이터베이스가 필요한 경우 DynamoDB를 활용하지 않고 있을 수 있습니다.",
            'steps': [
                "애플리케이션 요구 사항을 분석합니다.",
                "NoSQL 데이터베이스가 필요한지 평가합니다.",
                "필요한 경우 DynamoDB 테이블을 설계하고 생성합니다."
            ],
            'benefit': "DynamoDB는 완전 관리형 NoSQL 데이터베이스로, 확장성이 뛰어나고 지연 시간이 짧습니다.",
            'links': [
                {'url': 'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Introduction.html', 'title': 'DynamoDB 소개'},
                {'url': 'https://aws.amazon.com/dynamodb/getting-started/', 'title': 'DynamoDB 시작하기'}
            ]
        })
    
    return recommendations