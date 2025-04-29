import boto3

def get_ecs_data(aws_access_key, aws_secret_key, region):
    """ECS 클러스터 데이터 수집"""
    try:
        ecs_client = boto3.client(
            'ecs',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        # 클러스터 목록 가져오기
        clusters_response = ecs_client.list_clusters()
        clusters = []
        
        for cluster_arn in clusters_response['clusterArns']:
            cluster_details = ecs_client.describe_clusters(clusters=[cluster_arn])['clusters'][0]
            
            # 서비스 목록 가져오기
            services_response = ecs_client.list_services(cluster=cluster_arn)
            services_count = len(services_response.get('serviceArns', []))
            
            # 작업 목록 가져오기
            tasks_response = ecs_client.list_tasks(cluster=cluster_arn)
            tasks_count = len(tasks_response.get('taskArns', []))
            
            clusters.append({
                'name': cluster_details['clusterName'],
                'status': cluster_details['status'],
                'services': services_count,
                'tasks': tasks_count,
                'instances': cluster_details.get('registeredContainerInstancesCount', 0)
            })
        
        return {'clusters': clusters}
    except Exception as e:
        return {'error': str(e)}

def get_ecs_recommendations(clusters):
    """ECS 클러스터 추천 사항 수집"""
    recommendations = []
    
    for cluster in clusters:
        if cluster['instances'] > 0 and cluster['tasks'] == 0:
            recommendations.append({
                'service': 'ECS',
                'resource': cluster['name'],
                'severity': '중간',
                'message': f"클러스터에 인스턴스가 있지만 실행 중인 작업이 없습니다. 리소스를 최적화하세요.",
                'problem': f"ECS 클러스터 {cluster['name']}에 {cluster['instances']}개의 인스턴스가 있지만 실행 중인 작업이 없습니다.",
                'impact': "사용되지 않는 인스턴스는 불필요한 비용을 발생시킵니다.",
                'steps': [
                    "AWS 콘솔에서 ECS 서비스로 이동합니다.",
                    f"클러스터 {cluster['name']}를 선택합니다.",
                    "클러스터가 필요하지 않은 경우 인스턴스를 종료하거나 Auto Scaling 그룹을 조정합니다.",
                    "클러스터가 필요한 경우 작업을 배포하거나 Fargate로 마이그레이션을 고려합니다."
                ],
                'benefit': "사용하지 않는 인스턴스를 제거하면 월별 AWS 비용을 절감할 수 있습니다. Fargate로 마이그레이션하면 서버 관리 오버헤드를 줄일 수 있습니다.",
                'links': [
                    {'url': 'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ECS_instances.html', 'title': 'ECS 인스턴스 관리'},
                    {'url': 'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/AWS_Fargate.html', 'title': 'AWS Fargate 사용하기'}
                ]
            })
    
    return recommendations