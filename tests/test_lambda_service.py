import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Add the parent directory to the path so we can import the app modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.lambda_service import _check_debug_logs

class TestLambdaService(unittest.TestCase):
    
    @patch('boto3.client')
    def test_check_debug_logs_log_group_exists(self, mock_boto_client):
        # Setup mock for logs client
        mock_logs_client = MagicMock()
        mock_boto_client.return_value = mock_logs_client
        
        # Mock the describe_log_groups response to indicate log group exists
        mock_logs_client.describe_log_groups.return_value = {
            'logGroups': [
                {
                    'logGroupName': '/aws/lambda/test-function',
                    'creationTime': 1234567890,
                    'metricFilterCount': 0,
                    'arn': 'arn:aws:logs:region:account-id:log-group:/aws/lambda/test-function:*',
                    'storedBytes': 0
                }
            ]
        }
        
        # Mock the filter_log_events response with no debug logs
        mock_logs_client.filter_log_events.return_value = {
            'events': [
                {
                    'logStreamName': 'stream1',
                    'timestamp': 1234567890,
                    'message': 'INFO: Function executed successfully',
                    'ingestionTime': 1234567890,
                    'eventId': '12345'
                }
            ]
        }
        
        # Call the function
        result = _check_debug_logs('test-key', 'test-secret', 'us-east-1', 'test-function')
        
        # Verify the function returned False (no debug logs found)
        self.assertFalse(result)
        
        # Verify describe_log_groups was called with correct parameters
        mock_logs_client.describe_log_groups.assert_called_once_with(
            logGroupNamePrefix='/aws/lambda/test-function',
            limit=1
        )
        
        # Verify filter_log_events was called with correct parameters
        mock_logs_client.filter_log_events.assert_called_once_with(
            logGroupName='/aws/lambda/test-function',
            limit=100
        )
    
    @patch('boto3.client')
    def test_check_debug_logs_log_group_not_exists(self, mock_boto_client):
        # Setup mock for logs client
        mock_logs_client = MagicMock()
        mock_boto_client.return_value = mock_logs_client
        
        # Mock the describe_log_groups response to indicate log group doesn't exist
        mock_logs_client.describe_log_groups.return_value = {
            'logGroups': []
        }
        
        # Call the function
        result = _check_debug_logs('test-key', 'test-secret', 'us-east-1', 'test-function')
        
        # Verify the function returned False (log group doesn't exist)
        self.assertFalse(result)
        
        # Verify describe_log_groups was called with correct parameters
        mock_logs_client.describe_log_groups.assert_called_once_with(
            logGroupNamePrefix='/aws/lambda/test-function',
            limit=1
        )
        
        # Verify filter_log_events was NOT called
        mock_logs_client.filter_log_events.assert_not_called()
    
    @patch('boto3.client')
    def test_check_debug_logs_with_debug_logs(self, mock_boto_client):
        # Setup mock for logs client
        mock_logs_client = MagicMock()
        mock_boto_client.return_value = mock_logs_client
        
        # Mock the describe_log_groups response to indicate log group exists
        mock_logs_client.describe_log_groups.return_value = {
            'logGroups': [
                {
                    'logGroupName': '/aws/lambda/test-function',
                    'creationTime': 1234567890,
                    'metricFilterCount': 0,
                    'arn': 'arn:aws:logs:region:account-id:log-group:/aws/lambda/test-function:*',
                    'storedBytes': 0
                }
            ]
        }
        
        # Mock the filter_log_events response with debug logs
        mock_logs_client.filter_log_events.return_value = {
            'events': [
                {
                    'logStreamName': 'stream1',
                    'timestamp': 1234567890,
                    'message': 'INFO: Function executed successfully',
                    'ingestionTime': 1234567890,
                    'eventId': '12345'
                },
                {
                    'logStreamName': 'stream1',
                    'timestamp': 1234567891,
                    'message': 'DEBUG: console.log("Debug message")',
                    'ingestionTime': 1234567891,
                    'eventId': '12346'
                }
            ]
        }
        
        # Call the function
        result = _check_debug_logs('test-key', 'test-secret', 'us-east-1', 'test-function')
        
        # Verify the function returned True (debug logs found)
        self.assertTrue(result)
        
        # Verify describe_log_groups was called with correct parameters
        mock_logs_client.describe_log_groups.assert_called_once_with(
            logGroupNamePrefix='/aws/lambda/test-function',
            limit=1
        )
        
        # Verify filter_log_events was called with correct parameters
        mock_logs_client.filter_log_events.assert_called_once_with(
            logGroupName='/aws/lambda/test-function',
            limit=100
        )

if __name__ == '__main__':
    unittest.main()