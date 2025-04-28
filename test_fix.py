import unittest
from unittest.mock import patch, MagicMock
from app import app

class TestDynamoDBFunctionality(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.app = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()

    def tearDown(self):
        self.app_context.pop()

    @patch('boto3.client')
    def test_dynamodb_no_tables(self, mock_boto3_client):
        # Mock the DynamoDB client
        mock_dynamodb = MagicMock()
        mock_boto3_client.return_value = mock_dynamodb
        
        # Mock the list_tables response with no tables
        mock_dynamodb.list_tables.return_value = {'TableNames': []}
        
        # Mock the session data
        with self.app.session_transaction() as session:
            session['aws_access_key'] = 'test_key'
            session['aws_secret_key'] = 'test_secret'
            session['_user_id'] = '1'  # For flask-login
        
        # Make a request to the consolidated view
        response = self.app.get('/consolidated', follow_redirects=True)
        
        # Check that the response contains the expected message
        self.assertIn(b'DynamoDB \xed\x85\x8c\xec\x9d\xb4\xeb\xb8\x94\xec\x9d\xb4 \xec\x97\x86\xec\x8a\xb5\xeb\x8b\x88\xeb\x8b\xa4', response.data)
        
        # Check that the response contains the guidance text
        self.assertIn(b'AWS \xec\xbd\x98\xec\x86\x94\xec\x97\x90\xec\x84\x9c \xed\x85\x8c\xec\x9d\xb4\xeb\xb8\x94\xec\x9d\x84 \xec\x83\x9d\xec\x84\xb1\xed\x95\x98\xec\x84\xb8\xec\x9a\x94', response.data)

    @patch('boto3.client')
    def test_dynamodb_with_tables(self, mock_boto3_client):
        # Mock the DynamoDB client
        mock_dynamodb = MagicMock()
        mock_boto3_client.return_value = mock_dynamodb
        
        # Mock the list_tables response with a table
        mock_dynamodb.list_tables.return_value = {'TableNames': ['TestTable']}
        
        # Mock the describe_table response
        mock_dynamodb.describe_table.return_value = {
            'Table': {
                'TableName': 'TestTable',
                'TableStatus': 'ACTIVE',
                'ItemCount': 100,
                'TableSizeBytes': 1024 * 1024  # 1MB
            }
        }
        
        # Mock the session data
        with self.app.session_transaction() as session:
            session['aws_access_key'] = 'test_key'
            session['aws_secret_key'] = 'test_secret'
            session['_user_id'] = '1'  # For flask-login
        
        # Make a request to the consolidated view
        response = self.app.get('/consolidated', follow_redirects=True)
        
        # Check that the response contains the table name
        self.assertIn(b'TestTable', response.data)
        
        # Check that the response contains the table status
        self.assertIn(b'ACTIVE', response.data)

if __name__ == '__main__':
    unittest.main()