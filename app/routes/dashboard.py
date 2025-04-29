from flask import render_template, redirect, url_for, flash, session
from flask_login import login_required
from app import app
from app.services.aws_services import aws_services
from app.services.ec2 import get_ec2_data, get_ec2_recommendations
from app.services.s3 import get_s3_data, get_s3_recommendations
from app.services.rds import get_rds_data, get_rds_recommendations
from app.services.lambda_service import get_lambda_data, get_lambda_recommendations
from app.services.cloudwatch import get_cloudwatch_data, get_cloudwatch_recommendations
from app.services.dynamodb import get_dynamodb_data, get_dynamodb_recommendations
from app.services.ecs import get_ecs_data, get_ecs_recommendations
from app.services.eks import get_eks_data, get_eks_recommendations
from app.services.sns import get_sns_data, get_sns_recommendations
from app.services.sqs import get_sqs_data, get_sqs_recommendations
from app.services.apigateway import get_apigateway_data, get_apigateway_recommendations
from app.services.elasticache import get_elasticache_data, get_elasticache_recommendations
from app.services.route53 import get_route53_data, get_route53_recommendations
from app.services.iam import get_iam_data, get_iam_recommendations
from app.services.recommendations import get_all_recommendations

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
        all_services_data['ec2'] = get_ec2_data(aws_access_key, aws_secret_key, region)
        
        # S3 데이터
        all_services_data['s3'] = get_s3_data(aws_access_key, aws_secret_key, region)
        
        # RDS 데이터
        all_services_data['rds'] = get_rds_data(aws_access_key, aws_secret_key, region)
        
        # Lambda 데이터
        all_services_data['lambda'] = get_lambda_data(aws_access_key, aws_secret_key, region)
        
        # CloudWatch 데이터
        all_services_data['cloudwatch'] = get_cloudwatch_data(aws_access_key, aws_secret_key, region)
        
        # DynamoDB 데이터
        all_services_data['dynamodb'] = get_dynamodb_data(aws_access_key, aws_secret_key, region)
        
        # ECS 데이터
        all_services_data['ecs'] = get_ecs_data(aws_access_key, aws_secret_key, region)
        
        # EKS 데이터
        all_services_data['eks'] = get_eks_data(aws_access_key, aws_secret_key, region)
        
        # SNS 데이터
        all_services_data['sns'] = get_sns_data(aws_access_key, aws_secret_key, region)
        
        # SQS 데이터
        all_services_data['sqs'] = get_sqs_data(aws_access_key, aws_secret_key, region)
        
        # API Gateway 데이터
        all_services_data['apigateway'] = get_apigateway_data(aws_access_key, aws_secret_key, region)
        
        # ElastiCache 데이터
        all_services_data['elasticache'] = get_elasticache_data(aws_access_key, aws_secret_key, region)
        
        # Route 53 데이터
        all_services_data['route53'] = get_route53_data(aws_access_key, aws_secret_key, region)
        
        # IAM 데이터
        all_services_data['iam'] = get_iam_data(aws_access_key, aws_secret_key, region)
        
        # 모든 서비스에 대한 추천 사항 수집
        all_recommendations = get_all_recommendations(all_services_data, aws_access_key, aws_secret_key, region)
        
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

