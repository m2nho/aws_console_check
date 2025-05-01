# Changes Made to Fix Lambda Debug Logs Error

## Issue
When collecting Lambda function data, the application was encountering the following error:
```
Error checking debug logs: An error occurred (ResourceNotFoundException) when calling the FilterLogEvents operation: The specified log group does not exist.
```

This error occurred because the application was trying to check for debug logs in CloudWatch log groups that don't exist.

## Solution
Modified the `_check_debug_logs` function in `app/services/lambda_service.py` to check if the log group exists before attempting to filter log events:

1. Added a call to `describe_log_groups` to check if the log group exists
2. If the log group doesn't exist, the function returns `False` (no debug logs)
3. Only if the log group exists, the function proceeds to filter log events

## Tests Added
Created a new test file `tests/test_lambda_service.py` with the following test cases:

1. `test_check_debug_logs_log_group_exists`: Tests the case where the log group exists but no debug logs are found
2. `test_check_debug_logs_log_group_not_exists`: Tests the case where the log group doesn't exist
3. `test_check_debug_logs_with_debug_logs`: Tests the case where the log group exists and debug logs are found

## Dependencies Added
Added the following dependencies to `requirements.txt`:
- pytest==7.0.0
- pytest-mock==3.7.0

## How to Run Tests
```bash
# From the project root directory
pytest tests/test_lambda_service.py -v
```

## Expected Behavior
After this fix, when the application encounters a Lambda function without a corresponding CloudWatch log group, it will log an informational message and continue processing without raising an error.