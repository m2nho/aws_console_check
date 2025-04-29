from app.services.ec2 import get_ec2_recommendations
from app.services.s3 import get_s3_recommendations
from app.services.rds import get_rds_recommendations
from app.services.lambda_service import get_lambda_recommendations
from app.services.cloudwatch import get_cloudwatch_recommendations
from app.services.dynamodb import get_dynamodb_recommendations
from app.services.ecs import get_ecs_recommendations
from app.services.eks import get_eks_recommendations
from app.services.sns import get_sns_recommendations
from app.services.sqs import get_sqs_recommendations
from app.services.apigateway import get_apigateway_recommendations
from app.services.elasticache import get_elasticache_recommendations
from app.services.route53 import get_route53_recommendations
from app.services.iam import get_iam_recommendations

def get_all_recommendations(all_services_data, aws_access_key, aws_secret_key, region):
    """모든 서비스에 대한 추천 사항 수집"""
    all_recommendations = []
    
    # EC2 추천 사항
    if 'ec2' in all_services_data and 'instances' in all_services_data['ec2']:
        all_recommendations.extend(get_ec2_recommendations(all_services_data['ec2']['instances']))
    
    # S3 추천 사항
    if 's3' in all_services_data and 'buckets' in all_services_data['s3']:
        all_recommendations.extend(get_s3_recommendations(all_services_data['s3']['buckets'], aws_access_key, aws_secret_key, region))
    
    # RDS 추천 사항
    if 'rds' in all_services_data and 'instances' in all_services_data['rds']:
        all_recommendations.extend(get_rds_recommendations(all_services_data['rds']['instances']))
    
    # Lambda 추천 사항
    if 'lambda' in all_services_data and 'functions' in all_services_data['lambda']:
        all_recommendations.extend(get_lambda_recommendations(all_services_data['lambda']['functions']))
    
    # CloudWatch 추천 사항
    if 'cloudwatch' in all_services_data and 'alarms' in all_services_data['cloudwatch']:
        all_recommendations.extend(get_cloudwatch_recommendations(all_services_data['cloudwatch']['alarms']))
    
    # DynamoDB 추천 사항
    if 'dynamodb' in all_services_data and 'tables' in all_services_data['dynamodb']:
        all_recommendations.extend(get_dynamodb_recommendations(all_services_data['dynamodb']['tables']))
    
    # ECS 추천 사항
    if 'ecs' in all_services_data and 'clusters' in all_services_data['ecs']:
        all_recommendations.extend(get_ecs_recommendations(all_services_data['ecs']['clusters']))
    
    # EKS 추천 사항
    if 'eks' in all_services_data and 'clusters' in all_services_data['eks']:
        all_recommendations.extend(get_eks_recommendations(all_services_data['eks']['clusters']))
    
    # SNS 추천 사항
    if 'sns' in all_services_data and 'topics' in all_services_data['sns']:
        all_recommendations.extend(get_sns_recommendations(all_services_data['sns']['topics']))
    
    # SQS 추천 사항
    if 'sqs' in all_services_data and 'queues' in all_services_data['sqs']:
        all_recommendations.extend(get_sqs_recommendations(all_services_data['sqs']['queues']))
    
    # API Gateway 추천 사항
    if 'apigateway' in all_services_data and 'apis' in all_services_data['apigateway']:
        all_recommendations.extend(get_apigateway_recommendations(all_services_data['apigateway']['apis']))
    
    # ElastiCache 추천 사항
    if 'elasticache' in all_services_data and 'clusters' in all_services_data['elasticache']:
        all_recommendations.extend(get_elasticache_recommendations(all_services_data['elasticache']['clusters']))
    
    # Route 53 추천 사항
    if 'route53' in all_services_data and 'zones' in all_services_data['route53']:
        all_recommendations.extend(get_route53_recommendations(all_services_data['route53']['zones']))
    
    # IAM 추천 사항
    if 'iam' in all_services_data and 'users' in all_services_data['iam']:
        all_recommendations.extend(get_iam_recommendations(all_services_data['iam']['users']))
    
    return all_recommendations