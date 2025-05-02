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

# Changes Made to Show Uncollected Items in Red Boxes During Collection

## Issue
During data collection, users couldn't easily identify which services were still pending collection. The requirement was to show uncollected items in red boxes during the collection process.

## Solution
Modified the application to display all service sections during collection and highlight uncollected services with red boxes:

1. Added CSS styles for uncollected services (red border and shadow) and currently collecting services (blue border and shadow)
2. Modified the consolidated.html template to show all service sections during collection with appropriate styling
3. Updated the collection-progress.js file to dynamically update the styling of service sections as collection progresses
4. Modified the dashboard.py route to provide empty data structures for services that haven't been collected yet
5. Updated the EC2 section template to handle the "collecting" state with a loading indicator

## Files Modified
1. `/static/css/custom.css` - Added styles for uncollected and collecting services
2. `/templates/consolidated.html` - Modified to show all services during collection with conditional styling
3. `/static/js/collection-progress.js` - Added function to update service section styles dynamically
4. `/app/routes/dashboard.py` - Modified to provide empty data structures for uncollected services
5. `/templates/sections/ec2_section.html` - Added handling for the "collecting" state

## Expected Behavior
During data collection:
1. All service sections are displayed on the page
2. Services that haven't been collected yet are highlighted with red boxes
3. The currently collecting service is highlighted with a blue box
4. As each service is collected, its red box styling is removed
5. Users can easily identify which services are still pending collection

# Changes Made to Update Section Styling and Collection Progress Display

## Issue
The red effect on sections needed to be removed, and items in the collection progress container needed to be displayed with different colored badges based on their collection status.

## Solution
Modified the application to remove the red effect from sections and update the collection progress display:

1. Changed the styling for uncollected services from red to gray
2. Added different colored badges for services in different collection states:
   - Green badges for completed services
   - Yellow badges for pending services
   - Blue badges for the currently collecting service
3. Added a legend explaining the different badge colors

## Files Modified
1. `/static/css/custom.css` - Changed uncollected service styling from red to gray and added a new badge style for pending services
2. `/templates/consolidated.html` - Updated the alert message and added a legend for badge colors
3. `/static/js/collection-progress.js` - Modified to display different colored badges for services in different collection states

## Expected Behavior
After these changes:
1. Uncollected services are displayed with a gray border instead of red
2. In the collection progress container:
   - Completed services are displayed with green badges
   - Pending services are displayed with yellow badges
   - The currently collecting service is displayed with a blue badge
3. A legend explains the meaning of the different badge colors