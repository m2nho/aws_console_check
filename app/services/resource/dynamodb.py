import boto3

def get_dynamodb_data(aws_access_key, aws_secret_key, region):
    """DynamoDB 테이블 데이터 수집"""
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
        
        return {'tables': tables}
    except Exception as e:
        print(f"Error in DynamoDB service: {str(e)}")
        return {'tables': []}
