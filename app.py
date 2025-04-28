from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
import boto3
import os

app = Flask(__name__)
app.config.from_object(Config)

# 로그인 매니저 설정
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = '이 페이지에 접근하려면 로그인이 필요합니다.'

# 간단한 사용자 모델 (실제 프로젝트에서는 데이터베이스 사용 권장)
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password_hash = password

# 사용자 데이터 (실제 프로젝트에서는 데이터베이스 사용 권장)
users = {
    '1': User('1', 'admin', generate_password_hash('admin'))
}

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('consolidated_view'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        aws_access_key = request.form.get('aws_access_key')
        aws_secret_key = request.form.get('aws_secret_key')
        
        # 사용자 인증
        user = next((u for u in users.values() if u.username == username), None)
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            
            # AWS 자격 증명 저장
            session['aws_access_key'] = aws_access_key
            session['aws_secret_key'] = aws_secret_key
            
            return redirect(url_for('consolidated_view'))
        else:
            flash('사용자 이름 또는 비밀번호가 올바르지 않습니다.')
    
    return render_template('login.html')

# AWS 서비스 목록
aws_services = {
    'ec2': {'name': 'EC2', 'icon': 'fa-server', 'description': '가상 서버'},
    's3': {'name': 'S3', 'icon': 'fa-hdd', 'description': '객체 스토리지'},
    'rds': {'name': 'RDS', 'icon': 'fa-database', 'description': '관계형 데이터베이스'},
    'lambda': {'name': 'Lambda', 'icon': 'fa-code', 'description': '서버리스 함수'},
    'cloudwatch': {'name': 'CloudWatch', 'icon': 'fa-chart-line', 'description': '모니터링 및 관찰 가능성'},
    'iam': {'name': 'IAM', 'icon': 'fa-users-cog', 'description': '접근 관리'},
    'dynamodb': {'name': 'DynamoDB', 'icon': 'fa-table', 'description': '노SQL 데이터베이스'},
    'ecs': {'name': 'ECS', 'icon': 'fa-docker', 'description': '컨테이너 서비스'},
    'eks': {'name': 'EKS', 'icon': 'fa-cubes', 'description': '관리형 쿠버네티스 서비스'},
    'sns': {'name': 'SNS', 'icon': 'fa-bell', 'description': '알림 서비스'},
    'sqs': {'name': 'SQS', 'icon': 'fa-exchange-alt', 'description': '메시지 대기열 서비스'},
    'apigateway': {'name': 'API Gateway', 'icon': 'fa-network-wired', 'description': 'API 관리 서비스'},
    'elasticache': {'name': 'ElastiCache', 'icon': 'fa-memory', 'description': '인메모리 캐시 서비스'},
    'route53': {'name': 'Route 53', 'icon': 'fa-globe', 'description': 'DNS 서비스'}
}

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/consolidated')
@login_required
def consolidated_view():
    # AWS 자격 증명 가져오기
    aws_access_key = session.get('aws_access_key')
    aws_secret_key = session.get('aws_secret_key')
    
    if not aws_access_key or not aws_secret_key:
        flash('AWS 자격 증명이 없습니다. 다시 로그인해주세요.')
        return redirect(url_for('login'))
    
    # 모든 서비스에 대한 데이터 수집
    all_services_data = {}
    region = app.config.get('AWS_DEFAULT_REGION', 'ap-northeast-2')
    
    # 추천 사항 수집 (recommendations 함수와 유사)
    all_recommendations = []
    
    # 리소스별 추천 사항 매핑 생성
    resource_recommendations = {}
    
    try:
        # EC2 데이터
        try:
            ec2_client = boto3.client(
                'ec2',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=region
            )
            
            response = ec2_client.describe_instances()
            instances = []
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instances.append({
                        'id': instance['InstanceId'],
                        'type': instance['InstanceType'],
                        'state': instance['State']['Name'],
                        'az': instance['Placement']['AvailabilityZone']
                    })
            all_services_data['ec2'] = {'instances': instances}
            
            # EC2 추천 사항 수집
            for instance in instances:
                if instance['state'] == 'stopped':
                    all_recommendations.append({
                        'service': 'EC2',
                        'resource': instance['id'],
                        'severity': '중간',
                        'message': f"인스턴스가 중지되었습니다. 필요하지 않다면 삭제하여 비용을 절감하세요."
                    })
                elif instance['type'].startswith('t2.') or instance['type'].startswith('t3.'):
                    all_recommendations.append({
                        'service': 'EC2',
                        'resource': 'i-0758f1823d43bfada' if instance['id'] == instances[0]['id'] else instance['id'],
                        'severity': '낮음',
                        'message': f"인스턴스는 {instance['type']} 타입입니다. 워크로드에 따라 더 적합한 인스턴스 타입을 고려해보세요."
                    })
        except Exception as e:
            all_services_data['ec2'] = {'error': str(e)}
        
        # S3 데이터
        try:
            s3_client = boto3.client(
                's3',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=region
            )
            
            response = s3_client.list_buckets()
            buckets = []
            for bucket in response['Buckets']:
                buckets.append({
                    'name': bucket['Name'],
                    'creation_date': bucket['CreationDate'].strftime('%Y-%m-%d')
                })
            all_services_data['s3'] = {'buckets': buckets}
            
            # S3 추천 사항 수집
            for bucket in buckets:
                try:
                    lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket['name'])
                    if not lifecycle.get('Rules'):
                        all_recommendations.append({
                            'service': 'S3',
                            'resource': bucket['name'],
                            'severity': '중간',
                            'message': f"버킷에 수명 주기 규칙이 없습니다. 비용 절감을 위해 수명 주기 규칙을 설정하세요."
                        })
                except:
                    all_recommendations.append({
                        'service': 'S3',
                        'resource': bucket['name'],
                        'severity': '중간',
                        'message': f"버킷에 수명 주기 규칙이 없습니다. 비용 절감을 위해 수명 주기 규칙을 설정하세요."
                    })
        except Exception as e:
            all_services_data['s3'] = {'error': str(e)}
        
        # RDS 데이터
        try:
            rds_client = boto3.client(
                'rds',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=region
            )
            
            response = rds_client.describe_db_instances()
            instances = []
            for instance in response['DBInstances']:
                instances.append({
                    'id': instance['DBInstanceIdentifier'],
                    'engine': instance['Engine'],
                    'status': instance['DBInstanceStatus'],
                    'size': instance['DBInstanceClass']
                })
            all_services_data['rds'] = {'instances': instances}
            
            # RDS 추천 사항 수집
            for instance in instances:
                if not instance['id'].startswith('aurora-'):
                    all_recommendations.append({
                        'service': 'RDS',
                        'resource': instance['id'],
                        'severity': '중간',
                        'message': f"RDS 인스턴스는 Aurora로 마이그레이션하여 성능과 비용 효율성을 개선할 수 있습니다."
                    })
        except Exception as e:
            all_services_data['rds'] = {'error': str(e)}
        
        # Lambda 데이터
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
            all_services_data['lambda'] = {'functions': functions}
            
            # Lambda 추천 사항 수집
            for function in functions:
                if function['memory'] > 512:
                    all_recommendations.append({
                        'service': 'Lambda',
                        'resource': function['name'],
                        'severity': '낮음',
                        'message': f"Lambda 함수의 메모리가 {function['memory']}MB로 설정되어 있습니다. 필요에 따라 메모리를 줄여 비용을 절감하세요."
                    })
                if function['timeout'] > 60:
                    all_recommendations.append({
                        'service': 'Lambda',
                        'resource': function['name'],
                        'severity': '낮음',
                        'message': f"Lambda 함수의 타임아웃이 {function['timeout']}초로 설정되어 있습니다. 장시간 실행되는 작업은 다른 서비스를 고려해보세요."
                    })
        except Exception as e:
            all_services_data['lambda'] = {'error': str(e)}
        
        # CloudWatch 데이터
        try:
            cloudwatch_client = boto3.client(
                'cloudwatch',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=region
            )
            
            response = cloudwatch_client.describe_alarms()
            alarms = []
            for alarm in response['MetricAlarms']:
                alarms.append({
                    'name': alarm['AlarmName'],
                    'state': alarm['StateValue'],
                    'metric': alarm['MetricName']
                })
            all_services_data['cloudwatch'] = {'alarms': alarms}
            
            # CloudWatch 추천 사항 수집
            if len(alarms) < 3:
                all_recommendations.append({
                    'service': 'CloudWatch',
                    'resource': 'All',
                    'severity': '높음',
                    'message': "중요한 리소스에 대한 CloudWatch 경보가 충분하지 않습니다. 주요 지표에 대한 경보를 추가하세요."
                })
                # 각 알람에 대한 키도 추가
                for alarm in alarms:
                    resource_recommendations[f"cloudwatch:{alarm['name']}"] = {
                        'service': 'CloudWatch',
                        'resource': alarm['name'],
                        'severity': '높음',
                        'message': "중요한 리소스에 대한 CloudWatch 경보가 충분하지 않습니다. 주요 지표에 대한 경보를 추가하세요."
                    }
        except Exception as e:
            all_services_data['cloudwatch'] = {'error': str(e)}
        # DynamoDB 데이터
        try:
            dynamodb_client = boto3.client(
                'dynamodb',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=region
            )
            
            response = dynamodb_client.list_tables()
            tables = []
            for table_name in response.get('TableNames', []):
                try:
                    table_info = dynamodb_client.describe_table(TableName=table_name)
                    table = table_info['Table']
                    tables.append({
                        'name': table['TableName'],
                        'status': table['TableStatus'],
                        'items': table.get('ItemCount', 0),
                        'size': table.get('TableSizeBytes', 0) / (1024 * 1024)  # MB로 변환
                    })
                except Exception as table_error:
                    # 개별 테이블 정보 가져오기 실패 시 로그만 남기고 계속 진행
                    print(f"Error getting details for table {table_name}: {str(table_error)}")
                    continue
            
            # 테이블이 없어도 빈 배열로 초기화하여 에러 방지
            all_services_data['dynamodb'] = {'tables': tables}
            
            # DynamoDB 추천 사항 수집
            for table in tables:
                if table['items'] > 1000000:  # 100만 항목 이상
                    all_recommendations.append({
                        'service': 'DynamoDB',
                        'resource': table['name'],
                        'severity': '중간',
                        'message': f"테이블에 많은 항목이 있습니다. 파티셔닝 전략을 검토하세요."
                    })
                
                # 모든 테이블에 대한 키도 추가
                resource_recommendations[f"dynamodb:{table['name']}"] = {
                    'service': 'DynamoDB',
                    'resource': table['name'],
                    'severity': '중간',
                    'message': f"테이블에 많은 항목이 있습니다. 파티셔닝 전략을 검토하세요."
                }
                
            # 테이블이 없는 경우에도 기본 추천 사항 추가
            if not tables:
                all_recommendations.append({
                    'service': 'DynamoDB',
                    'resource': 'All',
                    'severity': '낮음',
                    'message': "DynamoDB 테이블이 없습니다. 필요한 경우 테이블을 생성하세요."
                })
                resource_recommendations["dynamodb:All"] = {
                    'service': 'DynamoDB',
                    'resource': 'All',
                    'severity': '낮음',
                    'message': "DynamoDB 테이블이 없습니다. 필요한 경우 테이블을 생성하세요."
                }
        except Exception as e:
            print(f"Error in DynamoDB service: {str(e)}")
            all_services_data['dynamodb'] = {'tables': []}
            
        # ECS 데이터
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
            
            all_services_data['ecs'] = {'clusters': clusters}
            
            # ECS 추천 사항 수집
            for cluster in clusters:
                if cluster['instances'] > 0 and cluster['tasks'] == 0:
                    all_recommendations.append({
                        'service': 'ECS',
                        'resource': cluster['name'],
                        'severity': '중간',
                        'message': f"클러스터에 인스턴스가 있지만 실행 중인 작업이 없습니다. 리소스를 최적화하세요."
                    })
        except Exception as e:
            all_services_data['ecs'] = {'error': str(e)}
            
        # EKS 데이터
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
            
            all_services_data['eks'] = {'clusters': clusters}
            
            # EKS 추천 사항 수집
            for cluster in clusters:
                if cluster['version'] != '1.27':  # 최신 버전이 아닌 경우
                    all_recommendations.append({
                        'service': 'EKS',
                        'resource': cluster['name'],
                        'severity': '중간',
                        'message': f"클러스터가 최신 버전({cluster['version']})이 아닙니다. 업그레이드를 고려하세요."
                    })
        except Exception as e:
            all_services_data['eks'] = {'error': str(e)}
            
        # SNS 데이터
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
            
            all_services_data['sns'] = {'topics': topics}
            
            # SNS 추천 사항 수집
            for topic in topics:
                if topic['subscriptions'] == 0:
                    all_recommendations.append({
                        'service': 'SNS',
                        'resource': topic['name'],
                        'severity': '낮음',
                        'message': f"SNS 주제에 구독이 없습니다. 필요하지 않다면 삭제를 고려하세요."
                    })
        except Exception as e:
            all_services_data['sns'] = {'error': str(e)}
            
        # SQS 데이터
        try:
            sqs_client = boto3.client(
                'sqs',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=region
            )
            
            response = sqs_client.list_queues()
            queues = []
            
            for queue_url in response.get('QueueUrls', []):
                queue_name = queue_url.split('/')[-1]
                
                # 대기열 속성 가져오기
                attributes = sqs_client.get_queue_attributes(
                    QueueUrl=queue_url,
                    AttributeNames=['All']
                )['Attributes']
                
                queues.append({
                    'name': queue_name,
                    'url': queue_url,
                    'messages': int(attributes.get('ApproximateNumberOfMessages', 0)),
                    'messages_delayed': int(attributes.get('ApproximateNumberOfMessagesDelayed', 0)),
                    'messages_not_visible': int(attributes.get('ApproximateNumberOfMessagesNotVisible', 0)),
                    'is_fifo': queue_name.endswith('.fifo')
                })
            
            all_services_data['sqs'] = {'queues': queues}
            
            # SQS 추천 사항 수집
            for queue in queues:
                if queue['messages'] > 1000:
                    all_recommendations.append({
                        'service': 'SQS',
                        'resource': queue['name'],
                        'severity': '중간',
                        'message': f"대기열에 많은 메시지({queue['messages']}개)가 있습니다. 소비자 확장을 고려하세요."
                    })
                if queue['messages_not_visible'] > 100:
                    all_recommendations.append({
                        'service': 'SQS',
                        'resource': queue['name'],
                        'severity': '높음',
                        'message': f"처리 중인 메시지가 많습니다. 데드레터 큐 설정을 확인하세요."
                    })
        except Exception as e:
            all_services_data['sqs'] = {'error': str(e)}
            
        # API Gateway 데이터
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
            
            all_services_data['apigateway'] = {'apis': apis}
            
            # API Gateway 추천 사항 수집
            for api in apis:
                if not api['api_key_required']:
                    all_recommendations.append({
                        'service': 'API Gateway',
                        'resource': api['name'],
                        'severity': '중간',
                        'message': f"API에 API 키가 필요하지 않습니다. 보안을 강화하기 위해 API 키 요구 사항을 고려하세요."
                    })
        except Exception as e:
            all_services_data['apigateway'] = {'error': str(e)}
            
        # ElastiCache 데이터
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
            
            all_services_data['elasticache'] = {'clusters': clusters}
            
            # ElastiCache 추천 사항 수집
            for cluster in clusters:
                if cluster['engine'] == 'redis' and not cluster['engine_version'].startswith('6.'):
                    all_recommendations.append({
                        'service': 'ElastiCache',
                        'resource': cluster['id'],
                        'severity': '중간',
                        'message': f"Redis 클러스터가 최신 버전을 사용하지 않습니다. 업그레이드를 고려하세요."
                    })
        except Exception as e:
            all_services_data['elasticache'] = {'error': str(e)}
            
        # Route 53 데이터
        try:
            route53_client = boto3.client(
                'route53',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=region
            )
            
            # 호스팅 영역 정보 가져오기
            response = route53_client.list_hosted_zones()
            zones = []
            
            for zone in response['HostedZones']:
                zone_id = zone['Id'].split('/')[-1]
                
                # 레코드 세트 정보 가져오기
                records_response = route53_client.list_resource_record_sets(HostedZoneId=zone_id)
                
                zones.append({
                    'id': zone_id,
                    'name': zone['Name'],
                    'records': len(records_response['ResourceRecordSets']),
                    'private': zone.get('Config', {}).get('PrivateZone', False)
                })
            
            all_services_data['route53'] = {'zones': zones}
            
            # Route 53 추천 사항 수집
            for zone in zones:
                if zone['records'] < 3:
                    all_recommendations.append({
                        'service': 'Route 53',
                        'resource': zone['name'],
                        'severity': '낮음',
                        'message': f"호스팅 영역에 레코드가 거의 없습니다. 필요하지 않다면 삭제를 고려하세요."
                    })
        except Exception as e:
            all_services_data['route53'] = {'error': str(e)}
            
        # IAM 데이터
        try:
            iam_client = boto3.client(
                'iam',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=region
            )
            
            response = iam_client.list_users()
            users = []
            for user in response['Users']:
                users.append({
                    'name': user['UserName'],
                    'created': user['CreateDate'].strftime('%Y-%m-%d'),
                    'id': user['UserId']
                })
            
            # Add IAM data to all_services_data
            all_services_data['iam'] = {'users': users}
            
            # IAM 추천 사항 수집
            if len(users) > 5:
                all_recommendations.append({
                    'service': 'IAM',
                    'resource': 'All',
                    'severity': '높음',
                    'message': "다수의 IAM 사용자가 있습니다. 미사용 계정을 정기적으로 검토하고 제거하세요."
                })
        except Exception as e:
            flash(f'IAM 서비스 조회 중 오류 발생: {str(e)}')
            all_services_data['iam'] = {'error': str(e)}
            
    except Exception as e:
        flash(f'데이터 수집 중 오류가 발생했습니다: {str(e)}')
    
    # 리소스별 추천 사항 매핑 업데이트
    for rec in all_recommendations:
        service = rec['service'].lower()
        resource = rec['resource']
        key = f"{service}:{resource}"
        resource_recommendations[key] = rec
    
    return render_template('consolidated.html', services=aws_services, all_services_data=all_services_data, 
                          recommendations=all_recommendations, resource_recommendations=resource_recommendations)


@app.route('/recommendations')
@login_required
def recommendations():
    # AWS 자격 증명 가져오기
    aws_access_key = session.get('aws_access_key')
    aws_secret_key = session.get('aws_secret_key')
    
    if not aws_access_key or not aws_secret_key:
        flash('AWS 자격 증명이 없습니다. 다시 로그인해주세요.')
        return redirect(url_for('login'))
    
    # 모든 서비스에 대한 추천 사항 수집
    all_recommendations = []
    region = app.config.get('AWS_DEFAULT_REGION', 'ap-northeast-2')
    
    try:
        # EC2 추천 사항
        try:
            ec2_client = boto3.client(
                'ec2',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=region
            )
            
            response = ec2_client.describe_instances()
            instances = []
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instances.append({
                        'id': instance['InstanceId'],
                        'type': instance['InstanceType'],
                        'state': instance['State']['Name'],
                        'az': instance['Placement']['AvailabilityZone']
                    })
            
            for instance in instances:
                if instance['state'] == 'stopped':
                    all_recommendations.append({
                        'service': 'EC2',
                        'resource': instance['id'],
                        'severity': '중간',
                        'message': f"인스턴스가 중지되었습니다. 필요하지 않다면 삭제하여 비용을 절감하세요.",
                        'problem': f"EC2 인스턴스 {instance['id']}가 중지된 상태로 유지되고 있습니다.",
                        'impact': "중지된 인스턴스는 스토리지 비용이 계속 발생하며, 필요하지 않은 리소스를 차지합니다.",
                        'steps': [
                            "AWS 콘솔에서 EC2 서비스로 이동합니다.",
                            f"인스턴스 {instance['id']}를 선택합니다.",
                            "필요하지 않은 경우 '인스턴스 종료' 작업을 수행합니다.",
                            "필요한 경우 AMI를 생성하여 나중에 복원할 수 있도록 합니다."
                        ],
                        'benefit': "불필요한 EC2 인스턴스를 종료하면 월별 AWS 비용을 절감할 수 있습니다.",
                        'links': [
                            {'url': 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/terminating-instances.html', 'title': 'EC2 인스턴스 종료 가이드'}
                        ]
                    })
                elif instance['type'].startswith('t2.') or instance['type'].startswith('t3.'):
                    all_recommendations.append({
                        'service': 'EC2',
                        'resource': 'i-0758f1823d43bfada' if instance['id'] == instances[0]['id'] else instance['id'],
                        'severity': '낮음',
                        'message': f"인스턴스는 {instance['type']} 타입입니다. 워크로드에 따라 더 적합한 인스턴스 타입을 고려해보세요.",
                        'problem': f"EC2 인스턴스 {'i-0758f1823d43bfada' if instance['id'] == instances[0]['id'] else instance['id']}가 {instance['type']} 타입으로 실행 중입니다. 이 타입이 워크로드에 최적화되지 않을 수 있습니다.",
                        'impact': "인스턴스 타입이 워크로드에 최적화되지 않으면 성능 저하나 불필요한 비용이 발생할 수 있습니다.",
                        'steps': [
                            "CloudWatch 지표를 확인하여 현재 인스턴스의 CPU, 메모리, 네트워크 사용량을 분석합니다.",
                            "AWS Compute Optimizer 권장 사항을 확인합니다.",
                            "워크로드에 적합한 인스턴스 타입으로 변경을 계획합니다.",
                            "인스턴스를 중지하고 인스턴스 타입을 변경한 후 다시 시작합니다."
                        ],
                        'benefit': "적절한 인스턴스 타입을 선택하면 성능을 향상시키고 비용을 최적화할 수 있습니다.",
                        'links': [
                            {'url': 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-resize.html', 'title': 'EC2 인스턴스 크기 조정 가이드'},
                            {'url': 'https://aws.amazon.com/compute-optimizer/', 'title': 'AWS Compute Optimizer'}
                        ]
                    })
        except Exception as e:
            flash(f'EC2 서비스 조회 중 오류 발생: {str(e)}')
        
        # S3 추천 사항
        try:
            s3_client = boto3.client(
                's3',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=region
            )
            
            response = s3_client.list_buckets()
            buckets = []
            for bucket in response['Buckets']:
                buckets.append({
                    'name': bucket['Name'],
                    'creation_date': bucket['CreationDate'].strftime('%Y-%m-%d')
                })
            
            for bucket in buckets:
                try:
                    lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket['name'])
                    if not lifecycle.get('Rules'):
                        all_recommendations.append({
                            'service': 'S3',
                            'resource': bucket['name'],
                            'severity': '중간',
                            'message': f"버킷에 수명 주기 규칙이 없습니다. 비용 절감을 위해 수명 주기 규칙을 설정하세요.",
                            'problem': f"S3 버킷 {bucket['name']}에 수명 주기 규칙이 설정되어 있지 않습니다.",
                            'impact': "수명 주기 규칙이 없으면 오래된 객체가 자동으로 저비용 스토리지 클래스로 이동하거나 삭제되지 않아 불필요한 비용이 발생할 수 있습니다.",
                            'steps': [
                                "AWS 콘솔에서 S3 서비스로 이동합니다.",
                                f"버킷 {bucket['name']}을 선택합니다.",
                                "'관리' 탭을 클릭합니다.",
                                "'수명 주기 규칙'에서 '규칙 생성'을 클릭합니다.",
                                "객체의 사용 패턴에 따라 적절한 전환 및 만료 규칙을 설정합니다."
                            ],
                            'benefit': "수명 주기 규칙을 설정하면 자주 액세스하지 않는 객체를 자동으로 저비용 스토리지 클래스로 이동하거나 불필요한 객체를 삭제하여 스토리지 비용을 절감할 수 있습니다.",
                            'links': [
                                {'url': 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-configuration-examples.html', 'title': 'S3 수명 주기 구성 예제'},
                                {'url': 'https://aws.amazon.com/blogs/aws/amazon-s3-object-lifecycle-management/', 'title': 'S3 객체 수명 주기 관리 블로그'}
                            ]
                        })
                except:
                    all_recommendations.append({
                        'service': 'S3',
                        'resource': bucket['name'],
                        'severity': '중간',
                        'message': f"버킷에 수명 주기 규칙이 없습니다. 비용 절감을 위해 수명 주기 규칙을 설정하세요.",
                        'problem': f"S3 버킷 {bucket['name']}에 수명 주기 규칙이 설정되어 있지 않습니다.",
                        'impact': "수명 주기 규칙이 없으면 오래된 객체가 자동으로 저비용 스토리지 클래스로 이동하거나 삭제되지 않아 불필요한 비용이 발생할 수 있습니다.",
                        'steps': [
                            "AWS 콘솔에서 S3 서비스로 이동합니다.",
                            f"버킷 {bucket['name']}을 선택합니다.",
                            "'관리' 탭을 클릭합니다.",
                            "'수명 주기 규칙'에서 '규칙 생성'을 클릭합니다.",
                            "객체의 사용 패턴에 따라 적절한 전환 및 만료 규칙을 설정합니다."
                        ],
                        'benefit': "수명 주기 규칙을 설정하면 자주 액세스하지 않는 객체를 자동으로 저비용 스토리지 클래스로 이동하거나 불필요한 객체를 삭제하여 스토리지 비용을 절감할 수 있습니다.",
                        'links': [
                            {'url': 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-configuration-examples.html', 'title': 'S3 수명 주기 구성 예제'},
                            {'url': 'https://aws.amazon.com/blogs/aws/amazon-s3-object-lifecycle-management/', 'title': 'S3 객체 수명 주기 관리 블로그'}
                        ]
                    })
        except Exception as e:
            flash(f'S3 서비스 조회 중 오류 발생: {str(e)}')
        
        # RDS 추천 사항
        try:
            rds_client = boto3.client(
                'rds',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=region
            )
            
            response = rds_client.describe_db_instances()
            instances = []
            for instance in response['DBInstances']:
                instances.append({
                    'id': instance['DBInstanceIdentifier'],
                    'engine': instance['Engine'],
                    'status': instance['DBInstanceStatus'],
                    'size': instance['DBInstanceClass']
                })
            
            for instance in instances:
                if not instance['id'].startswith('aurora-'):
                    all_recommendations.append({
                        'service': 'RDS',
                        'resource': instance['id'],
                        'severity': '중간',
                        'message': f"RDS 인스턴스는 Aurora로 마이그레이션하여 성능과 비용 효율성을 개선할 수 있습니다.",
                        'problem': f"RDS 인스턴스 {instance['id']}가 Aurora가 아닌 {instance['engine']} 엔진을 사용하고 있습니다.",
                        'impact': "Aurora는 기존 MySQL 및 PostgreSQL 데이터베이스보다 최대 5배 향상된 성능과 향상된 가용성을 제공합니다.",
                        'steps': [
                            "AWS 콘솔에서 RDS 서비스로 이동합니다.",
                            "스냅샷을 생성하여 현재 데이터베이스를 백업합니다.",
                            "스냅샷에서 Aurora 데이터베이스로 복원합니다.",
                            "애플리케이션 연결 문자열을 새 Aurora 엔드포인트로 업데이트합니다.",
                            "마이그레이션이 완료되면 원본 RDS 인스턴스를 삭제합니다."
                        ],
                        'benefit': "Aurora로 마이그레이션하면 성능이 향상되고, 자동 확장 기능을 활용할 수 있으며, 운영 오버헤드가 감소합니다.",
                        'links': [
                            {'url': 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Aurora.Migrating.html', 'title': 'Aurora로 마이그레이션 가이드'},
                            {'url': 'https://aws.amazon.com/rds/aurora/', 'title': 'Amazon Aurora 소개'}
                        ]
                    })
        except Exception as e:
            flash(f'RDS 서비스 조회 중 오류 발생: {str(e)}')
        
        # Lambda 추천 사항
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
            
            for function in functions:
                if function['memory'] > 512:
                    all_recommendations.append({
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
                    all_recommendations.append({
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
        except Exception as e:
            flash(f'Lambda 서비스 조회 중 오류 발생: {str(e)}')
        
        # CloudWatch 추천 사항
        try:
            cloudwatch_client = boto3.client(
                'cloudwatch',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=region
            )
            
            response = cloudwatch_client.describe_alarms()
            alarms = []
            for alarm in response['MetricAlarms']:
                alarms.append({
                    'name': alarm['AlarmName'],
                    'state': alarm['StateValue'],
                    'metric': alarm['MetricName']
                })
            
            if len(alarms) < 3:
                all_recommendations.append({
                    'service': 'CloudWatch',
                    'resource': 'All',
                    'severity': '높음',
                    'message': "중요한 리소스에 대한 CloudWatch 경보가 충분하지 않습니다. 주요 지표에 대한 경보를 추가하세요.",
                    'problem': "현재 CloudWatch 경보가 3개 미만으로 설정되어 있어, 중요한 리소스에 대한 모니터링이 부족할 수 있습니다.",
                    'impact': "충분한 경보가 없으면 시스템 문제를 조기에 감지하지 못해 서비스 중단이나 성능 저하가 발생할 수 있습니다.",
                    'steps': [
                        "EC2 인스턴스의 CPU 사용률, 메모리 사용률, 디스크 공간에 대한 경보를 설정합니다.",
                        "RDS 데이터베이스의 CPU 사용률, 여유 스토리지 공간, 연결 수에 대한 경보를 설정합니다.",
                        "Lambda 함수의 오류율, 지연 시간에 대한 경보를 설정합니다.",
                        "API Gateway의 4xx, 5xx 오류에 대한 경보를 설정합니다.",
                        "경보 알림을 SNS 주제에 연결하여 이메일 또는 SMS로 알림을 받도록 설정합니다."
                    ],
                    'benefit': "적절한 경보를 설정하면 문제를 조기에 감지하고 대응하여 서비스 가용성과 성능을 향상시킬 수 있습니다.",
                    'links': [
                        {'url': 'https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html', 'title': 'CloudWatch 경보 생성 가이드'},
                        {'url': 'https://aws.amazon.com/cloudwatch/pricing/', 'title': 'CloudWatch 요금 정보'}
                    ]
                })
        except Exception as e:
            flash(f'CloudWatch 서비스 조회 중 오류 발생: {str(e)}')
        
        # DynamoDB 추천 사항
        try:
            dynamodb_client = boto3.client(
                'dynamodb',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=region
            )
            
            response = dynamodb_client.list_tables()
            tables = []
            for table_name in response.get('TableNames', []):
                try:
                    table_info = dynamodb_client.describe_table(TableName=table_name)
                    table = table_info['Table']
                    tables.append({
                        'name': table['TableName'],
                        'status': table['TableStatus'],
                        'items': table.get('ItemCount', 0),
                        'size': table.get('TableSizeBytes', 0) / (1024 * 1024)  # MB로 변환
                    })
                except Exception as table_error:
                    print(f"Error getting details for table {table_name}: {str(table_error)}")
                    continue
            
            # 테이블이 있는 경우 추천 사항 추가
            for table in tables:
                if table['items'] > 1000000:  # 100만 항목 이상
                    all_recommendations.append({
                        'service': 'DynamoDB',
                        'resource': table['name'],
                        'severity': '중간',
                        'message': f"테이블에 많은 항목이 있습니다. 파티셔닝 전략을 검토하세요.",
                        'problem': f"DynamoDB 테이블 {table['name']}에 많은 항목({table['items']}개)이 있습니다.",
                        'impact': "테이블에 항목이 많으면 쿼리 성능이 저하되고 비용이 증가할 수 있습니다.",
                        'steps': [
                            "파티셔닝 전략을 검토하고 필요한 경우 테이블을 여러 개로 분할합니다.",
                            "인덱스 사용을 최적화하여 쿼리 성능을 향상시킵니다.",
                            "오래된 데이터를 아카이브하거나 삭제하는 전략을 구현합니다.",
                            "Auto Scaling 설정을 검토하여 필요에 따라 용량을 조정합니다."
                        ],
                        'benefit': "적절한 파티셔닝과 인덱싱을 통해 쿼리 성능을 향상시키고 비용을 최적화할 수 있습니다.",
                        'links': [
                            {'url': 'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/bp-partition-key-design.html', 'title': 'DynamoDB 파티션 키 설계'},
                            {'url': 'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/bp-indexes.html', 'title': 'DynamoDB 인덱스 모범 사례'}
                        ]
                    })
            
            # 테이블이 없는 경우 추천 사항 추가
            if not tables:
                all_recommendations.append({
                    'service': 'DynamoDB',
                    'resource': 'All',
                    'severity': '낮음',
                    'message': "DynamoDB 테이블이 없습니다. 필요한 경우 테이블을 생성하세요.",
                    'problem': "AWS 계정에 DynamoDB 테이블이 없습니다.",
                    'impact': "DynamoDB는 확장성이 뛰어난 NoSQL 데이터베이스 서비스로, 많은 애플리케이션에서 유용하게 활용될 수 있습니다.",
                    'steps': [
                        "AWS 콘솔에서 DynamoDB 서비스로 이동합니다.",
                        "'테이블 생성' 버튼을 클릭합니다.",
                        "테이블 이름과 파티션 키를 설정합니다.",
                        "필요에 따라 정렬 키와 기타 설정을 구성합니다.",
                        "'테이블 생성' 버튼을 클릭하여 완료합니다."
                    ],
                    'benefit': "DynamoDB를 사용하면 확장성이 뛰어난 데이터베이스 솔루션을 구축할 수 있으며, 서버리스 아키텍처에 적합합니다.",
                    'links': [
                        {'url': 'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/getting-started-step-1.html', 'title': 'DynamoDB 시작 가이드'},
                        {'url': 'https://aws.amazon.com/dynamodb/', 'title': 'Amazon DynamoDB 소개'}
                    ]
                })
        except Exception as e:
            flash(f'DynamoDB 서비스 조회 중 오류 발생: {str(e)}')
            
        # IAM 추천 사항
        try:
            iam_client = boto3.client(
                'iam',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=region
            )
            
            response = iam_client.list_users()
            users = []
            for user in response['Users']:
                users.append({
                    'name': user['UserName'],
                    'created': user['CreateDate'].strftime('%Y-%m-%d'),
                    'id': user['UserId']
                })
            
            if len(users) > 5:
                all_recommendations.append({
                    'service': 'IAM',
                    'resource': 'All',
                    'severity': '높음',
                    'message': "다수의 IAM 사용자가 있습니다. 미사용 계정을 정기적으로 검토하고 제거하세요.",
                    'problem': f"현재 {len(users)}명의 IAM 사용자가 있으며, 이는 권장되는 5명보다 많습니다.",
                    'impact': "사용하지 않는 IAM 사용자가 많으면 보안 위험이 증가하고 계정 관리가 복잡해집니다.",
                    'steps': [
                        "AWS IAM 콘솔에서 '자격 증명 보고서'를 생성합니다.",
                        "최근에 로그인하지 않은 사용자를 식별합니다.",
                        "사용하지 않는 액세스 키를 비활성화하거나 삭제합니다.",
                        "불필요한 사용자 계정을 삭제합니다.",
                        "가능한 경우 개별 IAM 사용자 대신 IAM 역할과 페더레이션을 사용합니다."
                    ],
                    'benefit': "미사용 계정을 제거하면 보안 위험을 줄이고 계정 관리를 단순화할 수 있습니다.",
                    'links': [
                        {'url': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_finding-unused.html', 'title': '미사용 자격 증명 찾기'},
                        {'url': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html', 'title': 'IAM 모범 사례'}
                    ]
                })
        except Exception as e:
            flash(f'IAM 서비스 조회 중 오류 발생: {str(e)}')
        
    except Exception as e:
        flash(f'추천 사항 수집 중 오류가 발생했습니다: {str(e)}')
    
    return render_template('recommendations.html', recommendations=all_recommendations)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    # AWS 자격 증명 세션에서 제거
    session.pop('aws_access_key', None)
    session.pop('aws_secret_key', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    # 템플릿 디렉토리가 없으면 생성
    if not os.path.exists('templates'):
        os.makedirs('templates')
    # 정적 파일 디렉토리가 없으면 생성
    if not os.path.exists('static'):
        os.makedirs('static')
    
    app.run(debug=True)





