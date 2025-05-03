import boto3

def get_route53_recommendations(zones):
    """Route 53 호스팅 영역 추천 사항 수집"""
    recommendations = []
    
    for zone in zones:
        if zone['records'] < 3:
            recommendations.append({
                'service': 'Route 53',
                'resource': zone['name'],
                'severity': '낮음',
                'message': f"호스팅 영역에 레코드가 거의 없습니다. 필요하지 않다면 삭제를 고려하세요.",
                'problem': f"Route 53 호스팅 영역 {zone['name']}에 레코드가 {zone['records']}개밖에 없습니다.",
                'impact': "사용하지 않는 호스팅 영역은 월별 요금이 발생하며, DNS 관리를 복잡하게 만들 수 있습니다.",
                'steps': [
                    "AWS 콘솔에서 Route 53 서비스로 이동합니다.",
                    f"호스팅 영역 {zone['name']}를 선택합니다.",
                    "호스팅 영역이 필요한지 확인합니다.",
                    "필요하지 않은 경우 모든 레코드를 백업한 후 호스팅 영역을 삭제합니다."
                ],
                'benefit': "불필요한 호스팅 영역을 제거하면 월별 비용을 절감하고 DNS 구성을 단순화할 수 있습니다.",
                'links': [
                    {'url': 'https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DeleteHostedZone.html', 'title': 'Route 53 호스팅 영역 삭제'},
                    {'url': 'https://aws.amazon.com/route53/pricing/', 'title': 'Route 53 요금 정보'}
                ]
            })
    
    return recommendations