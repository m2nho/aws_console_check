// 데이터 수집 진행 상황 관련 JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // 데이터 수집 기능 추가
    const startCollectionBtn = document.getElementById('start-collection');
    const progressContainer = document.getElementById('collection-progress-container');
    const currentServiceElement = document.getElementById('current-service');
    const progressBar = document.getElementById('progress-bar');
    const completedCountElement = document.getElementById('completed-count');
    const totalServicesElement = document.getElementById('total-services');
    const completedServicesList = document.getElementById('completed-services-list');
    const autoRefreshToggle = document.getElementById('auto-refresh');
    
    // 현재 페이지 확인
    const isConsolidatedPage = window.location.pathname.includes('/consolidated');
    
    // 서비스 ID와 이름 매핑
    const serviceMapping = {
        'EC2': 'ec2',
        'S3': 's3',
        'RDS': 'rds',
        'Lambda': 'lambda',
        'CloudWatch': 'cloudwatch',
        'IAM': 'iam',
        'DynamoDB': 'dynamodb',
        'ECS': 'ecs',
        'EKS': 'eks',
        'SNS': 'sns',
        'SQS': 'sqs',
        'API Gateway': 'apigateway',
        'ElastiCache': 'elasticache',
        'Route 53': 'route53'
    };
    
    // 데이터 수집 시작 버튼 이벤트 처리 - 통합 대시보드 페이지에서만 적용
    if (startCollectionBtn && isConsolidatedPage) {
        startCollectionBtn.addEventListener('click', function() {
            // 버튼 비활성화
            startCollectionBtn.disabled = true;
            startCollectionBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> 수집 시작 중...';
            
            // 자동 새로고침 비활성화
            if (autoRefreshToggle) {
                autoRefreshToggle.checked = false;
                autoRefreshToggle.disabled = true;
                if (typeof stopAutoRefresh === 'function') {
                    stopAutoRefresh();
                }
            }
            
            // 데이터 수집 시작 요청
            fetch('/start_collection', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'started') {
                    // 수집 시작 성공
                    console.log('데이터 수집이 시작되었습니다.');
                    
                    // 페이지 새로고침하여 진행 상황 표시
                    setTimeout(() => {
                        window.location.reload();
                    }, 1000);
                } else {
                    // 오류 발생
                    alert(data.message);
                    startCollectionBtn.disabled = false;
                    startCollectionBtn.textContent = '데이터 수집';
                    
                    // 자동 새로고침 다시 활성화
                    if (autoRefreshToggle) {
                        autoRefreshToggle.disabled = false;
                    }
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('데이터 수집 요청 중 오류가 발생했습니다.');
                startCollectionBtn.disabled = false;
                startCollectionBtn.textContent = '데이터 수집';
                
                // 자동 새로고침 다시 활성화
                if (autoRefreshToggle) {
                    autoRefreshToggle.disabled = false;
                }
            });
        });
    }
    
    // 데이터 수집 진행 상황 업데이트 함수
    function updateCollectionProgress() {
        if (!progressContainer) return;
        
        fetch('/collection_status')
            .then(response => response.json())
            .then(data => {
                // 현재 수집 중인 서비스 업데이트
                if (currentServiceElement) {
                    currentServiceElement.textContent = data.current_service || '완료됨';
                }
                
                // 진행률 업데이트
                if (progressBar) {
                    const percent = data.progress_percent;
                    progressBar.style.width = `${percent}%`;
                    progressBar.setAttribute('aria-valuenow', percent);
                    progressBar.textContent = `${percent}%`;
                }
                
                // 완료된 서비스 수 업데이트
                if (completedCountElement) {
                    completedCountElement.textContent = data.completed_services.length;
                }
                
                // 완료된 서비스 목록 업데이트
                if (completedServicesList) {
                    completedServicesList.innerHTML = '';
                    
                    // 완료된 서비스 배지 추가
                    data.completed_services.forEach(service => {
                        const badge = document.createElement('span');
                        badge.className = 'badge bg-success me-1 mb-1';
                        badge.textContent = service;
                        completedServicesList.appendChild(badge);
                    });
                    
                    // 수집 예정인 서비스 배지 추가 (완료되지 않은 서비스)
                    const allServices = Object.keys(serviceMapping);
                    const pendingServices = allServices.filter(service => 
                        !data.completed_services.includes(service) && 
                        service !== data.current_service
                    );
                    
                    pendingServices.forEach(service => {
                        const badge = document.createElement('span');
                        badge.className = 'badge bg-pending me-1 mb-1';
                        badge.textContent = service;
                        completedServicesList.appendChild(badge);
                    });
                    
                    // 현재 수집 중인 서비스 배지 추가
                    if (data.current_service) {
                        const badge = document.createElement('span');
                        badge.className = 'badge bg-primary me-1 mb-1';
                        badge.textContent = data.current_service + ' (수집 중)';
                        completedServicesList.appendChild(badge);
                    }
                }
                
                
                // 수집이 완료되면 페이지 새로고침
                if (!data.is_collecting && data.completed_services.length > 0) {
                    setTimeout(() => {
                        window.location.reload();
                    }, 1000);
                }
            })
            .catch(error => {
                console.error('Error:', error);
            });
    }
    
    
    // 데이터 수집 중인 경우 주기적으로 진행 상황 업데이트
    if (progressContainer) {
        // 3초마다 진행 상황 업데이트
        setInterval(updateCollectionProgress, 3000);
        // 초기 로드 시 한 번 업데이트
        updateCollectionProgress();
    }
});