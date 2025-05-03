# Import all resource functions for easy access
from app.services.resource.ec2 import get_ec2_data
from app.services.resource.lambda_service import get_lambda_data
from app.services.resource.s3 import get_s3_data
from app.services.resource.rds import get_rds_data
from app.services.resource.cloudwatch import get_cloudwatch_data
from app.services.resource.dynamodb import get_dynamodb_data
from app.services.resource.ecs import get_ecs_data
from app.services.resource.eks import get_eks_data
from app.services.resource.sns import get_sns_data
from app.services.resource.sqs import get_sqs_data
from app.services.resource.apigateway import get_apigateway_data
from app.services.resource.elasticache import get_elasticache_data
from app.services.resource.route53 import get_route53_data
from app.services.resource.iam import get_iam_data