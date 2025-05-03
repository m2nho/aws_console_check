import boto3


def get_eks_recommendations(clusters):
    """EKS 클러스터 추천 사항 수집"""
    recommendations = []
    
    for cluster in clusters:
        if cluster['version'] != '1.27':  # 최신 버전이 아닌 경우
            recommendations.append({
                'service': 'EKS',
                'resource': cluster['name'],
                'severity': '중간',
                'message': f"클러스터가 최신 버전({cluster['version']})이 아닙니다. 업그레이드를 고려하세요.",
                'problem': f"EKS 클러스터 {cluster['name']}가 최신 버전이 아닌 {cluster['version']} 버전을 사용하고 있습니다.",
                'impact': "이전 버전의 Kubernetes는 보안 취약점이 있을 수 있으며, 최신 기능을 사용할 수 없습니다.",
                'steps': [
                    "AWS 콘솔에서 EKS 서비스로 이동합니다.",
                    f"클러스터 {cluster['name']}를 선택합니다.",
                    "업그레이드 계획을 수립합니다.",
                    "클러스터 업그레이드 전에 워크로드 호환성을 테스트합니다.",
                    "클러스터를 업그레이드합니다."
                ],
                'benefit': "최신 버전으로 업그레이드하면 보안이 향상되고, 새로운 기능을 활용할 수 있으며, AWS 지원을 계속 받을 수 있습니다.",
                'links': [
                    {'url': 'https://docs.aws.amazon.com/eks/latest/userguide/update-cluster.html', 'title': 'EKS 클러스터 업데이트 가이드'},
                    {'url': 'https://kubernetes.io/releases/', 'title': 'Kubernetes 릴리스 정보'}
                ]
            })
    
    return recommendations