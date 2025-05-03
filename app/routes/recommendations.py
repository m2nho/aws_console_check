from flask import render_template, redirect, url_for, flash, session, send_from_directory
from flask_login import login_required, current_user
import os
from app import app

from app.services.recommendation import (
    get_ec2_recommendations, get_s3_recommendations, get_rds_recommendations, get_lambda_recommendations,
    get_cloudwatch_recommendations, get_dynamodb_recommendations, get_ecs_recommendations, get_eks_recommendations,
    get_sns_recommendations, get_sqs_recommendations, get_apigateway_recommendations, get_elasticache_recommendations,
    get_route53_recommendations, get_iam_recommendations
)
from app.routes.dashboard import collection_status

@app.route('/recommendations')
@login_required
def recommendations_view():
    # AWS 자격 증명 가져오기
    aws_access_key = session.get('aws_access_key')
    aws_secret_key = session.get('aws_secret_key')
    
    if not aws_access_key or not aws_secret_key:
        flash('AWS 자격 증명이 없습니다. 다시 로그인해주세요.')
        return redirect(url_for('login'))
    
    # 현재 사용자 ID
    user_id = current_user.get_id()
    
    # 데이터 수집 상태 확인
    global collection_status
    
    # 수집 중인 경우 진행 상태 표시
    if collection_status['is_collecting'] and collection_status['user_id'] == user_id:
        return render_template('recommendations.html', 
                              recommendations=[],
                              is_collecting=collection_status['is_collecting'],
                              current_service=collection_status['current_service'],
                              completed_services=collection_status['completed_services'],
                              total_services=collection_status['total_services'],
                              error=collection_status['error'])
    
    # 데이터 수집이 완료되지 않은 경우 (completed_services가 비어있는 경우)
    # 또는 현재 사용자의 데이터가 없는 경우
    if not collection_status['completed_services'] or collection_status['user_id'] != user_id:
        # 데이터 수집 버튼을 표시하는 페이지 렌더링
        flash('추천 사항을 보기 전에 먼저 데이터를 수집해야 합니다. 데이터 수집 버튼을 클릭하세요.')
        return render_template('recommendations.html', 
                              recommendations=[],
                              is_collecting=False,
                              current_service=None,
                              completed_services=[],
                              total_services=collection_status['total_services'],
                              error=None,
                              show_collection_message=True)
    
    # 데이터 수집이 완료된 경우, 이미 수집된 데이터를 기반으로 추천 사항 생성
    all_recommendations = []
    region = app.config.get('AWS_DEFAULT_REGION', 'ap-northeast-2')
    
    try:
        # 이미 수집된 데이터를 사용하여 추천 사항 생성
        if 'ec2' in collection_status['all_services_data'] and 'instances' in collection_status['all_services_data']['ec2']:
            all_recommendations.extend(get_ec2_recommendations(collection_status['all_services_data']['ec2']['instances']))
        
        if 'lambda' in collection_status['all_services_data'] and 'functions' in collection_status['all_services_data']['lambda']:
            all_recommendations.extend(get_lambda_recommendations(collection_status['all_services_data']['lambda']['functions']))
        
        # S3 추천 사항
        if 's3' in collection_status['all_services_data'] and 'buckets' in collection_status['all_services_data']['s3']:
            all_recommendations.extend(get_s3_recommendations(collection_status['all_services_data']['s3']['buckets'], aws_access_key, aws_secret_key, region))
        
        # # RDS 추천 사항
        # if 'rds' in collection_status['all_services_data'] and 'instances' in collection_status['all_services_data']['rds']:
        #     all_recommendations.extend(get_rds_recommendations(collection_status['all_services_data']['rds']['instances']))
        
        # # CloudWatch 추천 사항
        # if 'cloudwatch' in collection_status['all_services_data'] and 'alarms' in collection_status['all_services_data']['cloudwatch']:
        #     all_recommendations.extend(get_cloudwatch_recommendations(collection_status['all_services_data']['cloudwatch']['alarms']))
        
        # # IAM 추천 사항
        # if 'iam' in collection_status['all_services_data'] and 'users' in collection_status['all_services_data']['iam']:
        #     all_recommendations.extend(get_iam_recommendations(collection_status['all_services_data']['iam']['users']))
        
        
    except Exception as e:
        flash(f'추천 사항 생성 중 오류가 발생했습니다: {str(e)}')
    
    return render_template('recommendations.html', 
                          recommendations=all_recommendations,
                          is_collecting=False,
                          current_service=None,
                          completed_services=collection_status['completed_services'],
                          total_services=collection_status['total_services'],
                          error=None,
                          show_collection_message=False)

@app.route('/recommendation_conditions.md')
def serve_recommendation_conditions():
    """
    메인 목차 Markdown 파일을 제공하는 라우트
    """
    docs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'docs')
    return send_from_directory(docs_dir, 'recommendation_conditions.md', mimetype='text/markdown')

@app.route('/<service>/README.md')
def serve_service_recommendations(service):
    """
    서비스별 README.md 파일을 제공하는 라우트
    
    Args:
        service (str): 서비스 이름 (ec2, s3, rds 등)
    """
    docs_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        'docs',
        service
    )
    
    # 유효한 서비스 목록 정의
    valid_services = ['ec2', 's3', 'rds', 'lambda', 'iam', 'cloudwatch']
    
    # 잘못된 서비스 이름으로의 접근 방지
    if service not in valid_services:
        return "Invalid service", 404
        
    try:
        return send_from_directory(docs_dir, 'README.md', mimetype='text/markdown')
    except FileNotFoundError:
        return "Document not found", 404