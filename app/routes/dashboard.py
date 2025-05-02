from flask import render_template, redirect, url_for, flash, session, jsonify, request
from flask_login import login_required, current_user
from app import app
from app.services.aws_services import aws_services
from app.services.ec2 import get_ec2_data
from app.services.s3 import get_s3_data
from app.services.rds import get_rds_data
from app.services.lambda_service import get_lambda_data
from app.services.cloudwatch import get_cloudwatch_data
from app.services.dynamodb import get_dynamodb_data
from app.services.ecs import get_ecs_data
from app.services.eks import get_eks_data
from app.services.sns import get_sns_data
from app.services.sqs import get_sqs_data
from app.services.apigateway import get_apigateway_data
from app.services.elasticache import get_elasticache_data
from app.services.route53 import get_route53_data
from app.services.iam import get_iam_data
import threading
import time

# 데이터 수집 상태를 추적하기 위한 전역 변수
collection_status = {
    'is_collecting': False,
    'current_service': None,
    'completed_services': [],
    'total_services': 14,  # 총 서비스 수
    'error': None,
    'all_services_data': {},
    'user_id': None  # 사용자별 상태 추적을 위한 ID
}

# 데이터 수집 함수
def collect_data(aws_access_key, aws_secret_key, region, user_id):
    global collection_status
    
    # 사용자별 상태 초기화
    if collection_status['user_id'] != user_id:
        collection_status['all_services_data'] = {}
    
    collection_status['is_collecting'] = True
    collection_status['current_service'] = 'EC2'
    collection_status['completed_services'] = []
    collection_status['error'] = None
    collection_status['user_id'] = user_id
    
    try:
        # EC2 데이터
        collection_status['current_service'] = 'EC2'
        collection_status['all_services_data']['ec2'] = get_ec2_data(aws_access_key, aws_secret_key, region)
        collection_status['completed_services'].append('EC2')
        
        # S3 데이터
        collection_status['current_service'] = 'S3'
        collection_status['all_services_data']['s3'] = get_s3_data(aws_access_key, aws_secret_key, region)
        collection_status['completed_services'].append('S3')
        
        # RDS 데이터
        collection_status['current_service'] = 'RDS'
        collection_status['all_services_data']['rds'] = get_rds_data(aws_access_key, aws_secret_key, region)
        collection_status['completed_services'].append('RDS')
        
        # Lambda 데이터
        collection_status['current_service'] = 'Lambda'
        collection_status['all_services_data']['lambda'] = get_lambda_data(aws_access_key, aws_secret_key, region)
        collection_status['completed_services'].append('Lambda')
        
        # CloudWatch 데이터
        collection_status['current_service'] = 'CloudWatch'
        collection_status['all_services_data']['cloudwatch'] = get_cloudwatch_data(aws_access_key, aws_secret_key, region)
        collection_status['completed_services'].append('CloudWatch')
        
        # DynamoDB 데이터
        collection_status['current_service'] = 'DynamoDB'
        collection_status['all_services_data']['dynamodb'] = get_dynamodb_data(aws_access_key, aws_secret_key, region)
        collection_status['completed_services'].append('DynamoDB')
        
        # ECS 데이터
        collection_status['current_service'] = 'ECS'
        collection_status['all_services_data']['ecs'] = get_ecs_data(aws_access_key, aws_secret_key, region)
        collection_status['completed_services'].append('ECS')
        
        # EKS 데이터
        collection_status['current_service'] = 'EKS'
        collection_status['all_services_data']['eks'] = get_eks_data(aws_access_key, aws_secret_key, region)
        collection_status['completed_services'].append('EKS')
        
        # SNS 데이터
        collection_status['current_service'] = 'SNS'
        collection_status['all_services_data']['sns'] = get_sns_data(aws_access_key, aws_secret_key, region)
        collection_status['completed_services'].append('SNS')
        
        # SQS 데이터
        collection_status['current_service'] = 'SQS'
        collection_status['all_services_data']['sqs'] = get_sqs_data(aws_access_key, aws_secret_key, region)
        collection_status['completed_services'].append('SQS')
        
        # API Gateway 데이터
        collection_status['current_service'] = 'API Gateway'
        collection_status['all_services_data']['apigateway'] = get_apigateway_data(aws_access_key, aws_secret_key, region)
        collection_status['completed_services'].append('API Gateway')
        
        # ElastiCache 데이터
        collection_status['current_service'] = 'ElastiCache'
        collection_status['all_services_data']['elasticache'] = get_elasticache_data(aws_access_key, aws_secret_key, region)
        collection_status['completed_services'].append('ElastiCache')
        
        # Route 53 데이터
        collection_status['current_service'] = 'Route 53'
        collection_status['all_services_data']['route53'] = get_route53_data(aws_access_key, aws_secret_key, region)
        collection_status['completed_services'].append('Route 53')
        
        # IAM 데이터
        collection_status['current_service'] = 'IAM'
        collection_status['all_services_data']['iam'] = get_iam_data(aws_access_key, aws_secret_key, region)
        collection_status['completed_services'].append('IAM')
        
        # 수집 완료
        collection_status['current_service'] = None
        
    except Exception as e:
        collection_status['error'] = str(e)
    finally:
        collection_status['is_collecting'] = False

@app.route('/consolidated')
@login_required
def consolidated_view():
    # AWS 자격 증명 가져오기
    aws_access_key = session.get('aws_access_key')
    aws_secret_key = session.get('aws_secret_key')
    
    if not aws_access_key or not aws_secret_key:
        flash('AWS 자격 증명이 없습니다. 다시 로그인해주세요.')
        return redirect(url_for('login'))
    
    region = app.config.get('AWS_DEFAULT_REGION', 'ap-northeast-2')
    user_id = current_user.get_id()
    
    # 데이터 수집 상태 확인
    global collection_status
    
    # 수집 중인 경우 진행 상태 표시
    if collection_status['is_collecting'] and collection_status['user_id'] == user_id:
        # 모든 서비스에 대한 빈 데이터 구조 생성
        empty_services_data = {}
        for service_key in aws_services.keys():
            empty_services_data[service_key] = {'status': 'collecting'}
            
        # 이미 수집된 서비스 데이터는 유지
        for service_key, service_data in collection_status['all_services_data'].items():
            empty_services_data[service_key] = service_data
            
        return render_template('consolidated.html', 
                              services=aws_services, 
                              all_services_data=empty_services_data, 
                              resource_recommendations={},
                              is_collecting=collection_status['is_collecting'],
                              current_service=collection_status['current_service'],
                              completed_services=collection_status['completed_services'],
                              total_services=collection_status['total_services'],
                              error=collection_status['error'],
                              show_collection_message=False)
    
    # 데이터 수집이 완료되지 않은 경우 (completed_services가 비어있는 경우)
    # 또는 현재 사용자의 데이터가 없는 경우
    if not collection_status['completed_services'] or collection_status['user_id'] != user_id:
        # 데이터 수집 버튼을 표시하는 페이지 렌더링
        flash('서비스 정보를 보기 전에 먼저 데이터를 수집해야 합니다. 데이터 수집 버튼을 클릭하세요.')
        return render_template('consolidated.html', 
                              services=aws_services, 
                              all_services_data={}, 
                              resource_recommendations={},
                              is_collecting=False,
                              current_service=None,
                              completed_services=[],
                              total_services=collection_status['total_services'],
                              error=None,
                              show_collection_message=True)
    
    # 데이터가 이미 수집된 경우
    return render_template('consolidated.html', 
                          services=aws_services, 
                          all_services_data=collection_status['all_services_data'], 
                          resource_recommendations={},
                          is_collecting=False,
                          current_service=None,
                          completed_services=collection_status['completed_services'],
                          total_services=collection_status['total_services'],
                          error=collection_status['error'],
                          show_collection_message=False)

@app.route('/start_collection', methods=['POST'])
@login_required
def start_collection():
    # AWS 자격 증명 가져오기
    aws_access_key = session.get('aws_access_key')
    aws_secret_key = session.get('aws_secret_key')
    
    if not aws_access_key or not aws_secret_key:
        return jsonify({'status': 'error', 'message': 'AWS 자격 증명이 없습니다. 다시 로그인해주세요.'})
    
    global collection_status
    
    # 이미 수집 중인 경우
    if collection_status['is_collecting']:
        return jsonify({'status': 'in_progress', 'message': '데이터 수집이 이미 진행 중입니다.'})
    
    # 데이터 수집 시작
    region = app.config.get('AWS_DEFAULT_REGION', 'ap-northeast-2')
    user_id = current_user.get_id()
    
    # 백그라운드 스레드에서 데이터 수집 시작
    collection_thread = threading.Thread(
        target=collect_data, 
        args=(aws_access_key, aws_secret_key, region, user_id)
    )
    collection_thread.daemon = True
    collection_thread.start()
    
    return jsonify({'status': 'started', 'message': '데이터 수집이 시작되었습니다.'})

@app.route('/collection_status')
@login_required
def get_collection_status():
    global collection_status
    
    # 현재 사용자 ID
    user_id = current_user.get_id()
    
    # 다른 사용자의 데이터 수집 중인 경우
    if collection_status['user_id'] and collection_status['user_id'] != user_id:
        return jsonify({
            'is_collecting': False,
            'current_service': None,
            'completed_services': [],
            'total_services': collection_status['total_services'],
            'progress_percent': 0,
            'error': '다른 사용자의 데이터 수집 중입니다.'
        })
    
    # 진행률 계산
    progress_percent = 0
    if collection_status['total_services'] > 0:
        progress_percent = int((len(collection_status['completed_services']) / collection_status['total_services']) * 100)
    
    return jsonify({
        'is_collecting': collection_status['is_collecting'],
        'current_service': collection_status['current_service'],
        'completed_services': collection_status['completed_services'],
        'total_services': collection_status['total_services'],
        'progress_percent': progress_percent,
        'error': collection_status['error']
    })