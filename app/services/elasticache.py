import boto3

def get_elasticache_data(aws_access_key, aws_secret_key, region):
    """ElastiCache 클러스터 데이터 수집"""
    try:
        elasticache_client = boto3.client(
            'elasticache',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        # 캐시 클러스터 정보 가져오기
        response = elasticache_client.describe_cache_clusters()
        clusters = []
        
        for cluster in response['CacheClusters']:
            clusters.append({
                'id': cluster['CacheClusterId'],
                'engine': cluster['Engine'],
                'status': cluster['CacheClusterStatus'],
                'node_type': cluster['CacheNodeType'],
                'nodes': cluster['NumCacheNodes'],
                'engine_version': cluster['EngineVersion']
            })
        
        return {'clusters': clusters}
    except Exception as e:
        return {'error': str(e)}

def get_elasticache_recommendations(clusters):
    """ElastiCache 클러스터 추천 사항 수집"""
    recommendations = []
    
    for cluster in clusters:
        if cluster['engine'] == 'redis' and not cluster['engine_version'].startswith('6.'):
            recommendations.append({
                'service': 'ElastiCache',
                'resource': cluster['id'],
                'severity': '중간',
                'message': f"Redis 클러스터가 최신 버전을 사용하지 않습니다. 업그레이드를 고려하세요.",
                'problem': f"ElastiCache Redis 클러스터 {cluster['id']}가 최신 버전이 아닌 {cluster['engine_version']} 버전을 사용하고 있습니다.",
                'impact': "이전 버전의 Redis는 최신 기능, 성능 개선 및 보안 패치가 적용되지 않을 수 있습니다.",
                'steps': [
                    "AWS 콘솔에서 ElastiCache 서비스로 이동합니다.",
                    f"클러스터 {cluster['id']}를 선택합니다.",
                    "업그레이드 계획을 수립합니다.",
                    "유지 관리 기간 동안 엔진 버전 업그레이드를 수행합니다.",
                    "업그레이드 후 애플리케이션 기능을 테스트합니다."
                ],
                'benefit': "최신 버전으로 업그레이드하면 성능이 향상되고, 새로운 기능을 활용할 수 있으며, 보안이 강화됩니다.",
                'links': [
                    {'url': 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/VersionManagement.html', 'title': 'ElastiCache Redis 버전 관리'},
                    {'url': 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/RedisUpgradingEngineVersion.html', 'title': 'Redis 엔진 버전 업그레이드'}
                ]
            })
    
    return recommendations