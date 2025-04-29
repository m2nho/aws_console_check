import unittest
from app import app
from flask import session
import os
from unittest.mock import patch

class FlaskAppTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()

    def tearDown(self):
        self.app_context.pop()

    def test_index_redirect(self):
        """Test that the index route redirects to login page"""
        response = self.client.get('/', follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertTrue('/login' in response.location)

    def test_login_page_loads(self):
        """Test that the login page loads correctly"""
        response = self.client.get('/login')
        self.assertEqual(response.status_code, 200)
        self.assertIn('AWS 콘솔 체크 로그인', response.data.decode('utf-8'))
        self.assertIn('AWS 액세스 키 ID', response.data.decode('utf-8'))

    def test_login_with_valid_credentials(self):
        """Test login with valid credentials"""
        response = self.client.post('/login', data={
            'username': 'admin',
            'password': 'admin',
            'aws_access_key': 'test_access_key',
            'aws_secret_key': 'test_secret_key'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('AWS 서비스 통합 대시보드', response.data.decode('utf-8'))

    def test_login_with_invalid_credentials(self):
        """Test login with invalid credentials"""
        response = self.client.post('/login', data={
            'username': 'wrong',
            'password': 'wrong',
            'aws_access_key': 'test_access_key',
            'aws_secret_key': 'test_secret_key'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('사용자 이름 또는 비밀번호가 올바르지 않습니다', response.data.decode('utf-8'))

    def test_consolidated_view_requires_login(self):
        """Test that the consolidated view requires login"""
        response = self.client.get('/consolidated', follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertTrue('/login' in response.location)

    def test_logout(self):
        """Test logout functionality"""
        # First login
        self.client.post('/login', data={
            'username': 'admin',
            'password': 'admin',
            'aws_access_key': 'test_access_key',
            'aws_secret_key': 'test_secret_key'
        })
        
        # Then logout
        response = self.client.get('/logout', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('로그아웃되었습니다', response.data.decode('utf-8'))
        
        # Verify we're redirected to login page when trying to access consolidated view
        response = self.client.get('/consolidated', follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertTrue('/login' in response.location)
    


    def test_recommendations_requires_login(self):
        """Test that the recommendations page requires login"""
        response = self.client.get('/recommendations', follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertTrue('/login' in response.location)
    
    @patch('boto3.client')
    def test_recommendations_page_loads(self, mock_boto_client):
        """Test that the recommendations page loads correctly when logged in"""
        # Mock the boto3 client to avoid actual AWS API calls
        mock_boto_client.return_value.describe_instances.return_value = {'Reservations': []}
        mock_boto_client.return_value.list_buckets.return_value = {'Buckets': []}
        mock_boto_client.return_value.describe_db_instances.return_value = {'DBInstances': []}
        mock_boto_client.return_value.list_functions.return_value = {'Functions': []}
        mock_boto_client.return_value.describe_alarms.return_value = {'MetricAlarms': []}
        mock_boto_client.return_value.list_users.return_value = {'Users': []}
        
        # First login
        self.client.post('/login', data={
            'username': 'admin',
            'password': 'admin',
            'aws_access_key': 'test_access_key',
            'aws_secret_key': 'test_secret_key'
        })
        
        # Access recommendations page
        response = self.client.get('/recommendations', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('AWS 서비스 추천 사항', response.data.decode('utf-8'))
    
    def test_css_includes_toggle_styles(self):
        """Test that the CSS includes styles for toggle functionality"""
        # Get the CSS file
        response = self.client.get('/static/css/style.css')
        self.assertEqual(response.status_code, 200)
        css_content = response.data.decode('utf-8')
        
        # Check for the CSS rules
        self.assertIn('.modal-dialog {', css_content)
        self.assertIn('position: fixed', css_content)
        self.assertIn('transform: translate(-50%, -50%) !important', css_content)
        self.assertIn('.modal-content {', css_content)
        self.assertIn('transform: none !important', css_content)
        
        # Check for the z-index and event handling fixes
        self.assertIn('z-index: 1050', css_content)
        self.assertIn('z-index: 1051', css_content)
        self.assertIn('.modal-open {', css_content)
        self.assertIn('overflow: hidden', css_content)
        self.assertIn('pointer-events: auto', css_content)
        

        
    def test_js_includes_toggle_event_handling(self):
        """Test that the JavaScript file includes the toggle event handling"""
        # Get the JS file
        response = self.client.get('/static/js/main.js')
        self.assertEqual(response.status_code, 200)
        js_content = response.data.decode('utf-8')
        
        # Check for the event handling code
        self.assertIn('document.addEventListener(\'DOMContentLoaded\'', js_content)
        self.assertIn('Add tooltips', js_content)
        self.assertIn('Add confirmation for logout', js_content)
        
    # This test has been removed as we've replaced modal-fix.js with toggle-details.js
        
    def test_base_html_includes_js_files(self):
        """Test that the base.html includes the necessary JavaScript files"""
        # Login first to access a page that uses the base template
        self.client.post('/login', data={
            'username': 'admin',
            'password': 'admin',
            'aws_access_key': 'test_access_key',
            'aws_secret_key': 'test_secret_key'
        })
        
        # Get the consolidated view page
        response = self.client.get('/consolidated', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        html_content = response.data.decode('utf-8')
        
        # Check that the necessary scripts are included
        self.assertIn('static/js/main.js', html_content)
        self.assertIn('static/js/toggle-details.js', html_content)
        
    def test_recommendations_page_includes_toggle_details(self):
        """Test that the recommendations page includes toggle components"""
        # Mock the boto3 client to avoid actual AWS API calls
        with patch('boto3.client') as mock_boto_client:
            mock_boto_client.return_value.describe_instances.return_value = {
                'Reservations': [{
                    'Instances': [{
                        'InstanceId': 'i-12345',
                        'InstanceType': 't2.micro',
                        'State': {'Name': 'stopped'},
                        'Placement': {'AvailabilityZone': 'ap-northeast-2a'}
                    }]
                }]
            }
            mock_boto_client.return_value.list_buckets.return_value = {'Buckets': []}
            mock_boto_client.return_value.describe_db_instances.return_value = {'DBInstances': []}
            mock_boto_client.return_value.list_functions.return_value = {'Functions': []}
            mock_boto_client.return_value.describe_alarms.return_value = {'MetricAlarms': []}
            mock_boto_client.return_value.list_users.return_value = {'Users': []}
            
            # First login
            self.client.post('/login', data={
                'username': 'admin',
                'password': 'admin',
                'aws_access_key': 'test_access_key',
                'aws_secret_key': 'test_secret_key'
            })
            
            # Access recommendations page
            response = self.client.get('/recommendations', follow_redirects=True)
            self.assertEqual(response.status_code, 200)
            
            # Check for toggle elements in the recommendations page
            html_content = response.data.decode('utf-8')
            self.assertIn('toggle-details', html_content)
            self.assertIn('collapse', html_content)
            self.assertIn('table-responsive', html_content)
            self.assertIn('table-sortable', html_content)
            self.assertIn('filter-btn', html_content)
            self.assertIn('severity-filter-btn', html_content)
            self.assertIn('모두 보기', html_content)
            self.assertIn('세부 작업 보기', html_content)



    def test_checklist_toggle_js_exists_and_works(self):
        """Test that the checklist-toggle.js file exists and contains the necessary functionality"""
        # Get the checklist-toggle.js file
        response = self.client.get('/static/js/checklist-toggle.js')
        self.assertEqual(response.status_code, 200)
        js_content = response.data.decode('utf-8')
        
        # Check for the specific toggle functionality code
        self.assertIn('Checklist toggle functionality for AWS Console Check application', js_content)
        self.assertIn('const toggleSwitches = document.querySelectorAll(\'.form-check-input[data-item-id]\')', js_content)
        self.assertIn('loadToggleStates()', js_content)
        self.assertIn('saveToggleState(', js_content)
        self.assertIn('updateItemUI(', js_content)
        self.assertIn('localStorage.getItem', js_content)
        self.assertIn('localStorage.setItem', js_content)
    
    def test_toggle_details_js_exists_and_works(self):
        """Test that the toggle-details.js file exists and contains the necessary functionality"""
        # Get the toggle-details.js file
        response = self.client.get('/static/js/toggle-details.js')
        self.assertEqual(response.status_code, 200)
        js_content = response.data.decode('utf-8')
        
        # Check for the specific toggle functionality code
        self.assertIn('Toggle functionality for recommendation details', js_content)
        self.assertIn('const detailButtons = document.querySelectorAll(\'button[data-bs-toggle="collapse"]\')', js_content)
        self.assertIn('targetCollapse.addEventListener(\'shown.bs.collapse\'', js_content)
        self.assertIn('targetCollapse.addEventListener(\'hidden.bs.collapse\'', js_content)
        self.assertIn('button.textContent = \'닫기\'', js_content)
        self.assertIn('button.textContent = originalText', js_content)
        self.assertIn('btn-outline-primary', js_content)
        self.assertIn('btn-primary', js_content)
        
        # Check for the new auto-expand functionality
        self.assertIn('Automatically expand all sections when details are shown', js_content)
        self.assertIn('expandableSections.forEach', js_content)
        self.assertIn('section.classList.add(\'expanded\')', js_content)
        self.assertIn('content.style.maxHeight = content.scrollHeight + \'px\'', js_content)
    
    def test_base_html_includes_toggle_details_js(self):
        """Test that the base.html includes the toggle-details.js script"""
        # Login first to access a page that uses the base template
        self.client.post('/login', data={
            'username': 'admin',
            'password': 'admin',
            'aws_access_key': 'test_access_key',
            'aws_secret_key': 'test_secret_key'
        })
        
        # Get the consolidated view page instead of dashboard
        response = self.client.get('/consolidated', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        html_content = response.data.decode('utf-8')
        
        # Check that the toggle-details.js script is included
        self.assertIn('static/js/toggle-details.js', html_content)

    def test_recommendation_simple_js_exists_and_works(self):
        """Test that the recommendation-simple.js file exists and contains the necessary functionality"""
        # Get the recommendation-simple.js file
        response = self.client.get('/static/js/recommendation-simple.js')
        self.assertEqual(response.status_code, 200)
        js_content = response.data.decode('utf-8')
        
        # Check for the specific functionality code
        self.assertIn('Simplified Recommendation Page JavaScript', js_content)
        self.assertIn('const filterButtons = document.querySelectorAll(\'.filter-btn\')', js_content)
        self.assertIn('const recommendationItems = document.querySelectorAll(\'.recommendation-item\')', js_content)
        self.assertIn('button.addEventListener(\'click\'', js_content)
        self.assertIn('filterButtons.forEach(btn => btn.classList.remove(\'active\'))', js_content)
        self.assertIn('this.classList.add(\'active\')', js_content)
        self.assertIn('const filter = this.getAttribute(\'data-filter\')', js_content)
        self.assertIn('item.getAttribute(\'data-service\')', js_content)
        self.assertIn('const toggleButtons = document.querySelectorAll(\'.toggle-details\')', js_content)
        self.assertIn('const expanded = this.getAttribute(\'aria-expanded\')', js_content)
        self.assertIn('card.scrollIntoView({ behavior: \'smooth\', block: \'nearest\' })', js_content)
    
    def test_recommendation_card_updated_css_exists_and_works(self):
        """Test that the recommendation-card-updated.css file exists and contains the necessary styles"""
        # Get the recommendation-card-updated.css file
        response = self.client.get('/static/css/recommendation-card-updated.css')
        self.assertEqual(response.status_code, 200)
        css_content = response.data.decode('utf-8')
        
        # Check for the specific CSS rules
        self.assertIn('.recommendation-card {', css_content)
        self.assertIn('.recommendation-card .card-header {', css_content)
        self.assertIn('.recommendation-card .card-body {', css_content)
        self.assertIn('.recommendation-card .toggle-details {', css_content)
        self.assertIn('.recommendation-card .collapse {', css_content)
        self.assertIn('.recommendation-card h6.fw-bold {', css_content)
        self.assertIn('.recommendation-card ol.ps-3,', css_content)
        self.assertIn('.recommendation-card li.mb-1 {', css_content)
        
        # Check for the new dropdown style elements
        self.assertIn('transition: all 0.3s ease', css_content)
        self.assertIn('box-shadow: none', css_content)
        self.assertIn('border: 1px solid rgba(0,0,0,.125)', css_content)
        self.assertIn('border-radius: 8px', css_content)
        self.assertIn('padding-left: 2rem !important', css_content)
        self.assertIn('margin-bottom: 0.5rem !important', css_content)
    
    @patch('boto3.client')
    def test_consolidated_view_requires_login(self, mock_boto_client):
        """Test that the consolidated view requires login"""
        response = self.client.get('/consolidated', follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertTrue('/login' in response.location)
    
    @patch('boto3.client')
    def test_consolidated_view_loads_correctly(self, mock_boto_client):
        """Test that the consolidated view loads correctly when logged in"""
        # Mock the boto3 client to avoid actual AWS API calls
        mock_boto_client.return_value.describe_instances.return_value = {'Reservations': []}
        mock_boto_client.return_value.list_buckets.return_value = {'Buckets': []}
        mock_boto_client.return_value.describe_db_instances.return_value = {'DBInstances': []}
        mock_boto_client.return_value.list_functions.return_value = {'Functions': []}
        mock_boto_client.return_value.describe_alarms.return_value = {'MetricAlarms': []}
        mock_boto_client.return_value.list_users.return_value = {'Users': []}
        
        # First login
        self.client.post('/login', data={
            'username': 'admin',
            'password': 'admin',
            'aws_access_key': 'test_access_key',
            'aws_secret_key': 'test_secret_key'
        })
        
        # Access consolidated view
        response = self.client.get('/consolidated', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        html_content = response.data.decode('utf-8')
        
        # Check for the consolidated view elements
        self.assertIn('AWS 서비스 통합 대시보드', html_content)
        self.assertIn('모든 AWS 서비스의 정보를 한 페이지에서 확인하세요', html_content)
        self.assertIn('모두 펼치기', html_content)
        self.assertIn('모두 접기', html_content)
        self.assertIn('자동 새로고침', html_content)
        
        # Check for service sections
        self.assertIn('ec2-section', html_content)
        self.assertIn('s3-section', html_content)
        self.assertIn('rds-section', html_content)
        self.assertIn('lambda-section', html_content)
        self.assertIn('cloudwatch-section', html_content)
        self.assertIn('iam-section', html_content)
        
        # Check for table elements
        self.assertIn('table-responsive', html_content)
        self.assertIn('table-striped', html_content)
        self.assertIn('table-hover', html_content)
        self.assertIn('table-sortable', html_content)
        
    @patch('boto3.client')
    def test_consolidated_template_css_blocks(self, mock_boto_client):
        """Test that the consolidated template has properly structured CSS blocks"""
        # Mock the boto3 client to avoid actual AWS API calls
        mock_boto_client.return_value.describe_instances.return_value = {'Reservations': []}
        mock_boto_client.return_value.list_buckets.return_value = {'Buckets': []}
        mock_boto_client.return_value.describe_db_instances.return_value = {'DBInstances': []}
        mock_boto_client.return_value.list_functions.return_value = {'Functions': []}
        mock_boto_client.return_value.describe_alarms.return_value = {'MetricAlarms': []}
        mock_boto_client.return_value.list_users.return_value = {'Users': []}
        
        # First login
        self.client.post('/login', data={
            'username': 'admin',
            'password': 'admin',
            'aws_access_key': 'test_access_key',
            'aws_secret_key': 'test_secret_key'
        })
        
        # Access consolidated view
        response = self.client.get('/consolidated', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        html_content = response.data.decode('utf-8')
        
        # Check that the CSS is properly included in the extra_css block
        self.assertIn('{% block extra_css %}', html_content)
        self.assertIn('<style>', html_content)
        self.assertIn('.service-section .card-header {', html_content)
        self.assertIn('cursor: pointer;', html_content)
        self.assertIn('</style>', html_content)
        self.assertIn('{% endblock %}', html_content)
        
        # Check that the JavaScript is properly included in the extra_js block
        self.assertIn('{% block extra_js %}', html_content)
        self.assertIn('<script>', html_content)
        self.assertIn('document.addEventListener(\'DOMContentLoaded\'', html_content)
        self.assertIn('</script>', html_content)
        self.assertIn('{% endblock %}', html_content)
    
    @patch('boto3.client')
    def test_consolidated_view_with_ec2_data(self, mock_boto_client):
        """Test that the consolidated view displays EC2 data correctly"""
        # Mock the boto3 client to return test data for EC2
        mock_boto_client.return_value.describe_instances.return_value = {
            'Reservations': [{
                'Instances': [{
                    'InstanceId': 'i-12345',
                    'InstanceType': 't2.micro',
                    'State': {'Name': 'running'},
                    'Placement': {'AvailabilityZone': 'ap-northeast-2a'}
                }]
            }]
        }
        mock_boto_client.return_value.list_buckets.return_value = {'Buckets': []}
        mock_boto_client.return_value.describe_db_instances.return_value = {'DBInstances': []}
        mock_boto_client.return_value.list_functions.return_value = {'Functions': []}
        mock_boto_client.return_value.describe_alarms.return_value = {'MetricAlarms': []}
        mock_boto_client.return_value.list_users.return_value = {'Users': []}
        
        # First login
        self.client.post('/login', data={
            'username': 'admin',
            'password': 'admin',
            'aws_access_key': 'test_access_key',
            'aws_secret_key': 'test_secret_key'
        })
        
        # Access consolidated view
        response = self.client.get('/consolidated', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        html_content = response.data.decode('utf-8')
        
        # Check for EC2 instance data
        self.assertIn('i-12345', html_content)
        self.assertIn('t2.micro', html_content)
        self.assertIn('실행 중', html_content)
        self.assertIn('ap-northeast-2a', html_content)
        

        
    def test_navbar_has_link_to_consolidated_view(self):
        """Test that the navbar has a link to the consolidated view"""
        # First login
        self.client.post('/login', data={
            'username': 'admin',
            'password': 'admin',
            'aws_access_key': 'test_access_key',
            'aws_secret_key': 'test_secret_key'
        })
        
        # Access any page
        response = self.client.get('/consolidated', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        html_content = response.data.decode('utf-8')
        
        # Check for the link to consolidated view in the navbar
        self.assertIn('<a class="nav-link" href="{{ url_for(\'consolidated_view\') }}">통합 대시보드</a>', html_content)
        
        # Check that there is no dashboard link
        self.assertNotIn('<a class="nav-link" href="{{ url_for(\'dashboard\') }}">대시보드</a>', html_content)
        

    @patch('boto3.client')
    def test_consolidated_view_has_detail_buttons(self, mock_boto_client):
        """Test that the consolidated view has 'see detail' buttons"""
        # Mock the boto3 client to return test data
        mock_boto_client.return_value.describe_instances.return_value = {
            'Reservations': [{
                'Instances': [{
                    'InstanceId': 'i-12345',
                    'InstanceType': 't2.micro',
                    'State': {'Name': 'running'},
                    'Placement': {'AvailabilityZone': 'ap-northeast-2a'}
                }]
            }]
        }
        mock_boto_client.return_value.list_buckets.return_value = {'Buckets': []}
        mock_boto_client.return_value.describe_db_instances.return_value = {'DBInstances': []}
        mock_boto_client.return_value.list_functions.return_value = {'Functions': []}
        mock_boto_client.return_value.describe_alarms.return_value = {'MetricAlarms': []}
        mock_boto_client.return_value.list_users.return_value = {'Users': []}
        
        # First login
        self.client.post('/login', data={
            'username': 'admin',
            'password': 'admin',
            'aws_access_key': 'test_access_key',
            'aws_secret_key': 'test_secret_key'
        })
        
        # Access consolidated view
        response = self.client.get('/consolidated', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        html_content = response.data.decode('utf-8')
        
        # Check for the 'see detail' buttons
        self.assertIn('세부 작업 보기', html_content)
        self.assertIn('toggle-details', html_content)
        self.assertIn('data-bs-toggle="collapse"', html_content)
        self.assertIn('data-bs-target="#details-ec2-', html_content)
        
        # Check for the collapse elements
        self.assertIn('collapse" id="details-ec2-', html_content)
        self.assertIn('card card-body bg-light border-0 p-3 m-2', html_content)
        
        # Check for the detail content sections
        self.assertIn('인스턴스 정보', html_content)
        self.assertIn('권장 작업', html_content)
        self.assertIn('관련 링크', html_content)
    
    @patch('boto3.client')
    def test_consolidated_view_detail_content(self, mock_boto_client):
        """Test that the consolidated view detail content is correct"""
        # Mock the boto3 client to return test data
        mock_boto_client.return_value.describe_instances.return_value = {
            'Reservations': [{
                'Instances': [{
                    'InstanceId': 'i-12345',
                    'InstanceType': 't2.micro',
                    'State': {'Name': 'stopped'},
                    'Placement': {'AvailabilityZone': 'ap-northeast-2a'}
                }]
            }]
        }
        mock_boto_client.return_value.list_buckets.return_value = {'Buckets': []}
        mock_boto_client.return_value.describe_db_instances.return_value = {'DBInstances': []}
        mock_boto_client.return_value.list_functions.return_value = {'Functions': []}
        mock_boto_client.return_value.describe_alarms.return_value = {'MetricAlarms': []}
        mock_boto_client.return_value.list_users.return_value = {'Users': []}
        
        # First login
        self.client.post('/login', data={
            'username': 'admin',
            'password': 'admin',
            'aws_access_key': 'test_access_key',
            'aws_secret_key': 'test_secret_key'
        })
        
        # Access consolidated view
        response = self.client.get('/consolidated', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        html_content = response.data.decode('utf-8')
        
        # Check for specific content in the detail view for a stopped EC2 instance
        self.assertIn('인스턴스가 중지된 상태입니다', html_content)
        self.assertIn('필요하지 않다면 삭제하여 비용을 절감하세요', html_content)
        self.assertIn('EC2 인스턴스 수명 주기 관리', html_content)
        self.assertIn('AWS Compute Optimizer', html_content)
        
        # Check for the styling of the detail view
        self.assertIn('details-row', html_content)
        self.assertIn('fw-bold text-muted mb-2', html_content)
        self.assertIn('fas fa-server me-2', html_content)
        self.assertIn('fas fa-tasks me-2', html_content)
        self.assertIn('fas fa-link me-2', html_content)
        
    @patch('boto3.client')
    def test_unique_filter_with_length(self, mock_boto_client):
        """Test that the unique filter followed by length works correctly in the consolidated view"""
        # Mock the boto3 client to return test data with multiple instance types
        mock_boto_client.return_value.describe_instances.return_value = {
            'Reservations': [{
                'Instances': [
                    {
                        'InstanceId': 'i-12345',
                        'InstanceType': 't2.micro',
                        'State': {'Name': 'running'},
                        'Placement': {'AvailabilityZone': 'ap-northeast-2a'}
                    },
                    {
                        'InstanceId': 'i-67890',
                        'InstanceType': 't2.micro',  # Same type as first instance
                        'State': {'Name': 'running'},
                        'Placement': {'AvailabilityZone': 'ap-northeast-2b'}
                    },
                    {
                        'InstanceId': 'i-abcde',
                        'InstanceType': 't3.medium',  # Different type
                        'State': {'Name': 'stopped'},
                        'Placement': {'AvailabilityZone': 'ap-northeast-2c'}
                    }
                ]
            }]
        }
        mock_boto_client.return_value.list_buckets.return_value = {'Buckets': []}
        mock_boto_client.return_value.describe_db_instances.return_value = {'DBInstances': []}
        mock_boto_client.return_value.list_functions.return_value = {'Functions': []}
        mock_boto_client.return_value.describe_alarms.return_value = {'MetricAlarms': []}
        mock_boto_client.return_value.list_users.return_value = {'Users': []}
        
        # First login
        self.client.post('/login', data={
            'username': 'admin',
            'password': 'admin',
            'aws_access_key': 'test_access_key',
            'aws_secret_key': 'test_secret_key'
        })
        
        # Access consolidated view
        response = self.client.get('/consolidated', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        html_content = response.data.decode('utf-8')
        
        # Check that the page renders correctly with the unique instance types count (should be 2)
        # This verifies our fix for the TypeError: object of type 'generator' has no len()
        self.assertIn('인스턴스 타입</h5>', html_content)
        self.assertIn('2 종류', html_content)  # Should show 2 unique instance types
        
    @patch('boto3.client')
    def test_consolidated_view_detail_shows_recommendation_data(self, mock_boto_client):
        """Test that the consolidated view detail shows the same recommendation data as in the recommendations page"""
        # Mock the boto3 client to return test data
        mock_boto_client.return_value.describe_instances.return_value = {
            'Reservations': [{
                'Instances': [{
                    'InstanceId': 'i-12345',
                    'InstanceType': 't2.micro',
                    'State': {'Name': 'stopped'},
                    'Placement': {'AvailabilityZone': 'ap-northeast-2a'}
                }]
            }]
        }
        mock_boto_client.return_value.list_buckets.return_value = {'Buckets': []}
        mock_boto_client.return_value.describe_db_instances.return_value = {'DBInstances': []}
        mock_boto_client.return_value.list_functions.return_value = {'Functions': []}
        mock_boto_client.return_value.describe_alarms.return_value = {'MetricAlarms': []}
        mock_boto_client.return_value.list_users.return_value = {'Users': []}
        
        # First login
        self.client.post('/login', data={
            'username': 'admin',
            'password': 'admin',
            'aws_access_key': 'test_access_key',
            'aws_secret_key': 'test_secret_key'
        })
        
        # Access consolidated view
        response = self.client.get('/consolidated', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        consolidated_html = response.data.decode('utf-8')
        
        # Access recommendations page
        response = self.client.get('/recommendations', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        recommendations_html = response.data.decode('utf-8')
        
        # Check that the consolidated view detail contains the same key elements as the recommendations page
        # Check for problem section
        self.assertIn('문제점</h6>', consolidated_html)
        self.assertIn('EC2 인스턴스 i-12345가 중지된 상태로 유지되고 있습니다', consolidated_html)
        
        # Check for impact section
        self.assertIn('영향</h6>', consolidated_html)
        self.assertIn('중지된 인스턴스는 스토리지 비용이 계속 발생하며, 필요하지 않은 리소스를 차지합니다', consolidated_html)
        
        # Check for recommended actions section
        self.assertIn('권장 조치</h6>', consolidated_html)
        self.assertIn('AWS 콘솔에서 EC2 서비스로 이동합니다', consolidated_html)
        self.assertIn('인스턴스 i-12345를 선택합니다', consolidated_html)
        self.assertIn('필요하지 않은 경우 \'인스턴스 종료\' 작업을 수행합니다', consolidated_html)
        
        # Check for benefits section
        self.assertIn('기대 효과</h6>', consolidated_html)
        self.assertIn('불필요한 EC2 인스턴스를 종료하면 월별 AWS 비용을 절감할 수 있습니다', consolidated_html)
        
        # Check for reference links section
        self.assertIn('관련 링크</h6>', consolidated_html)
        self.assertIn('EC2 인스턴스 종료 가이드', consolidated_html)
        
        # Verify that the recommendations page also contains similar elements
        self.assertIn('문제점</h6>', recommendations_html)
        self.assertIn('영향</h6>', recommendations_html)
        self.assertIn('권장 조치</h6>', recommendations_html)
        self.assertIn('기대 효과</h6>', recommendations_html)
        self.assertIn('참고 자료</h6>', recommendations_html)


if __name__ == '__main__':
    unittest.main()




















    @patch('boto3.client')
    def test_recommendations_page_has_table_layout(self, mock_boto_client):
        """Test that the recommendations page has a table layout with detail buttons"""
        # Mock the boto3 client to return test data
        mock_boto_client.return_value.describe_instances.return_value = {
            'Reservations': [{
                'Instances': [{
                    'InstanceId': 'i-12345',
                    'InstanceType': 't2.micro',
                    'State': {'Name': 'stopped'},
                    'Placement': {'AvailabilityZone': 'ap-northeast-2a'}
                }]
            }]
        }
        mock_boto_client.return_value.list_buckets.return_value = {'Buckets': []}
        mock_boto_client.return_value.describe_db_instances.return_value = {'DBInstances': []}
        mock_boto_client.return_value.list_functions.return_value = {'Functions': []}
        mock_boto_client.return_value.describe_alarms.return_value = {'MetricAlarms': []}
        mock_boto_client.return_value.list_users.return_value = {'Users': []}
        
        # First login
        self.client.post('/login', data={
            'username': 'admin',
            'password': 'admin',
            'aws_access_key': 'test_access_key',
            'aws_secret_key': 'test_secret_key'
        })
        
        # Access recommendations page
        response = self.client.get('/recommendations', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        html_content = response.data.decode('utf-8')
        
        # Check for table layout elements
        self.assertIn('table-responsive', html_content)
        self.assertIn('table table-striped table-hover table-sortable', html_content)
        self.assertIn('<th>서비스</th>', html_content)
        self.assertIn('<th>리소스</th>', html_content)
        self.assertIn('<th>메시지</th>', html_content)
        self.assertIn('<th>위험도</th>', html_content)
        self.assertIn('<th>작업</th>', html_content)
        
        # Check for detail buttons
        self.assertIn('세부 작업 보기', html_content)
        self.assertIn('toggle-details', html_content)
        self.assertIn('data-bs-toggle="collapse"', html_content)
        self.assertIn('data-bs-target="#details-rec-', html_content)
        
        # Check for severity filter buttons
        self.assertIn('모든 위험도', html_content)
        self.assertIn('btn-outline-danger severity-filter-btn', html_content)
        self.assertIn('btn-outline-warning severity-filter-btn', html_content)
        self.assertIn('btn-outline-info severity-filter-btn', html_content)
        self.assertIn('data-filter="높음"', html_content)
        self.assertIn('data-filter="중간"', html_content)
        self.assertIn('data-filter="낮음"', html_content)
    
    def test_aws_services_dictionary_structure(self):
        """Test that the aws_services dictionary has the correct structure"""
        # First login
        self.client.post('/login', data={
            'username': 'admin',
            'password': 'admin',
            'aws_access_key': 'test_access_key',
            'aws_secret_key': 'test_secret_key'
        })
        
        # Access consolidated view
        response = self.client.get('/consolidated', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        html_content = response.data.decode('utf-8')
        
        # Check that the service names are displayed correctly
        self.assertIn('EC2', html_content)
        self.assertIn('S3', html_content)
        self.assertIn('RDS', html_content)
        self.assertIn('Lambda', html_content)
        self.assertIn('CloudWatch', html_content)
        self.assertIn('IAM', html_content)
        
        # Check that the raw dictionary is not displayed
        self.assertNotIn("{'name': 'EC2', 'icon': 'fa-server', 'description': '가상 서버'}", html_content)
        self.assertNotIn("{'name': 'S3', 'icon': 'fa-hdd', 'description': '객체 스토리지'}", html_content)
        
    def test_new_aws_services_added(self):
        """Test that the new AWS services have been added"""
        # First login
        self.client.post('/login', data={
            'username': 'admin',
            'password': 'admin',
            'aws_access_key': 'test_access_key',
            'aws_secret_key': 'test_secret_key'
        })
        
        # Access dashboard page
        response = self.client.get('/consolidated', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Import the aws_services dictionary from app.services.aws_services
        from app.services.aws_services import aws_services
        
        # Check that the new services are in the dictionary
        self.assertIn('dynamodb', aws_services)
        self.assertIn('ecs', aws_services)
        self.assertIn('eks', aws_services)
        self.assertIn('sns', aws_services)
        self.assertIn('sqs', aws_services)
        self.assertIn('apigateway', aws_services)
        self.assertIn('elasticache', aws_services)
        self.assertIn('route53', aws_services)
        
        # Check that each service has the required properties
        for service_key, service_info in aws_services.items():
            self.assertIn('name', service_info)
            self.assertIn('icon', service_info)
            self.assertIn('description', service_info)
    @patch('boto3.client')
    def test_consolidated_view_no_risk_indicators_in_detail_view(self, mock_boto_client):
        """Test that the consolidated view doesn't show risk indicators next to issues in the detailed view"""
        # Mock the boto3 client to return test data
        mock_boto_client.return_value.describe_instances.return_value = {
            'Reservations': [{
                'Instances': [{
                    'InstanceId': 'i-12345',
                    'InstanceType': 't2.micro',
                    'State': {'Name': 'stopped'},
                    'Placement': {'AvailabilityZone': 'ap-northeast-2a'}
                }]
            }]
        }
        mock_boto_client.return_value.list_buckets.return_value = {
            'Buckets': [
                {
                    'Name': 'test-bucket',
                    'CreationDate': '2023-01-01 00:00:00'
                }
            ]
        }
        mock_boto_client.return_value.describe_db_instances.return_value = {'DBInstances': []}
        mock_boto_client.return_value.list_functions.return_value = {'Functions': []}
        mock_boto_client.return_value.describe_alarms.return_value = {'MetricAlarms': []}
        mock_boto_client.return_value.list_users.return_value = {'Users': []}
        
        # First login
        self.client.post('/login', data={
            'username': 'admin',
            'password': 'admin',
            'aws_access_key': 'test_access_key',
            'aws_secret_key': 'test_secret_key'
        })
        
        # Access consolidated view
        response = self.client.get('/consolidated', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        html_content = response.data.decode('utf-8')
        
        # Check that the "문제점" headers don't have risk indicators next to them
        # This pattern would match any badge next to "문제점" in the detail view
        self.assertNotIn('<i class="fas fa-exclamation-triangle me-2"></i>문제점</h6>\n                                                <span class="badge', html_content)
        self.assertNotIn('<i class="fas fa-exclamation-triangle me-2"></i>문제점\n                                                    <span class="badge', html_content)
        
        # Check that the "문제점" headers are present without badges
        self.assertIn('<i class="fas fa-exclamation-triangle me-2"></i>문제점</h6>', html_content)
        
        # Check that risk indicators are still present in the table columns
        self.assertIn('<span class="badge bg-warning">중간</span>', html_content)
        self.assertIn('<span class="badge bg-secondary">없음</span>', html_content)











