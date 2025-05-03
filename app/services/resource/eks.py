import boto3

def get_eks_data(aws_access_key, aws_secret_key, region):
    """EKS 클러스터 데이터 수집"""
    try:
        eks_client = boto3.client(
            'eks',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        response = eks_client.list_clusters()
        clusters = []
        
        for cluster_name in response['clusters']:
            cluster_info = eks_client.describe_cluster(name=cluster_name)['cluster']
            clusters.append({
                'name': cluster_info['name'],
                'status': cluster_info['status'],
                'version': cluster_info['version'],
                'platform_version': cluster_info.get('platformVersion', 'N/A'),
                'created_at': cluster_info['createdAt'].strftime('%Y-%m-%d')
            })
        
        return {'clusters': clusters}
    except Exception as e:
        return {'error': str(e)}
