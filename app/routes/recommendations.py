from flask import render_template, redirect, url_for, flash, session
from flask_login import login_required
from app import app
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

@app.route('/recommendations')
@login_required
def recommendations_view():
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
        ec2_data = get_ec2_data(aws_access_key, aws_secret_key, region)
        if 'instances' in ec2_data:
            all_recommendations.extend(get_ec2_recommendations(ec2_data['instances']))
        
        # S3 추천 사항
        s3_data = get_s3_data(aws_access_key, aws_secret_key, region)
        if 'buckets' in s3_data:
            all_recommendations.extend(get_s3_recommendations(s3_data['buckets'], aws_access_key, aws_secret_key, region))
        
        # RDS 추천 사항
        rds_data = get_rds_data(aws_access_key, aws_secret_key, region)
        if 'instances' in rds_data:
            all_recommendations.extend(get_rds_recommendations(rds_data['instances']))
        
        # Lambda 추천 사항
        lambda_data = get_lambda_data(aws_access_key, aws_secret_key, region)
        if 'functions' in lambda_data:
            all_recommendations.extend(get_lambda_recommendations(lambda_data['functions']))
        
        # CloudWatch 추천 사항
        cloudwatch_data = get_cloudwatch_data(aws_access_key, aws_secret_key, region)
        if 'alarms' in cloudwatch_data:
            all_recommendations.extend(get_cloudwatch_recommendations(cloudwatch_data['alarms']))
        
        # DynamoDB 추천 사항
        dynamodb_data = get_dynamodb_data(aws_access_key, aws_secret_key, region)
        if 'tables' in dynamodb_data:
            all_recommendations.extend(get_dynamodb_recommendations(dynamodb_data['tables']))
        
        # ECS 추천 사항
        ecs_data = get_ecs_data(aws_access_key, aws_secret_key, region)
        if 'clusters' in ecs_data:
            all_recommendations.extend(get_ecs_recommendations(ecs_data['clusters']))
        
        # EKS 추천 사항
        eks_data = get_eks_data(aws_access_key, aws_secret_key, region)
        if 'clusters' in eks_data:
            all_recommendations.extend(get_eks_recommendations(eks_data['clusters']))
        
        # SNS 추천 사항
        sns_data = get_sns_data(aws_access_key, aws_secret_key, region)
        if 'topics' in sns_data:
            all_recommendations.extend(get_sns_recommendations(sns_data['topics']))
        
        # SQS 추천 사항
        sqs_data = get_sqs_data(aws_access_key, aws_secret_key, region)
        if 'queues' in sqs_data:
            all_recommendations.extend(get_sqs_recommendations(sqs_data['queues']))
        
        # API Gateway 추천 사항
        apigateway_data = get_apigateway_data(aws_access_key, aws_secret_key, region)
        if 'apis' in apigateway_data:
            all_recommendations.extend(get_apigateway_recommendations(apigateway_data['apis']))
        
        # ElastiCache 추천 사항
        elasticache_data = get_elasticache_data(aws_access_key, aws_secret_key, region)
        if 'clusters' in elasticache_data:
            all_recommendations.extend(get_elasticache_recommendations(elasticache_data['clusters']))
        
        # Route 53 추천 사항
        route53_data = get_route53_data(aws_access_key, aws_secret_key, region)
        if 'zones' in route53_data:
            all_recommendations.extend(get_route53_recommendations(route53_data['zones']))
        
        # IAM 추천 사항
        iam_data = get_iam_data(aws_access_key, aws_secret_key, region)
        if 'users' in iam_data:
            all_recommendations.extend(get_iam_recommendations(iam_data['users']))
        
    except Exception as e:
        flash(f'추천 사항 수집 중 오류가 발생했습니다: {str(e)}')
    
    return render_template('recommendations.html', recommendations=all_recommendations)