# AWS 콘솔 체크 (AWS Console Check)

AWS 서비스 사용 현황을 확인하고 최적화 추천 사항을 제공하는 Flask 웹 애플리케이션입니다.

## 기능 (Features)

- AWS 자격 증명을 통한 안전한 로그인 (Secure login through AWS credentials)
- AWS 서비스 사용 현황 모니터링 (Real-time AWS service usage monitoring)
- 서비스별 최적화 추천 사항 제공 (Service-specific optimization recommendations)
- 통합 대시보드 뷰 (Consolidated dashboard view)
- 상세한 리소스 분석 (Detailed resource analysis)
- 위험도 기반 알림 (Risk-based alerts)
- 자동 새로고침 기능 (Automatic refresh functionality)

## 지원하는 AWS 서비스 (Supported AWS Services)

- EC2 (인스턴스 관리)
- S3 (버킷 관리)
- RDS (데이터베이스 관리)
- Lambda (서버리스 함수)
- CloudWatch (모니터링)
- IAM (사용자 및 권한)
- DynamoDB (NoSQL 데이터베이스)
- ECS (컨테이너 서비스)
- EKS (쿠버네티스 서비스)
- SNS (알림 서비스)
- SQS (메시지 큐)
- API Gateway
- ElastiCache
- Route 53 (DNS 서비스)

## 사전 요구 사항 (Prerequisites)

- Python 3.7 이상
- pip (Python 패키지 관리자)
- AWS 계정 및 액세스 키
- 웹 브라우저 (Chrome, Firefox, Safari 권장)

## 설치 방법 (Installation)

1. 저장소 클론
```bash
git clone https://github.com/m2nho/aws-console-check.git
cd aws-console-check
```

2. 가상 환경 생성 및 활성화
```bash
# Linux/macOS
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

3. 의존성 설치
```bash
pip install -r requirements.txt
```

4. 환경 변수 설정
```bash
# Linux/macOS
export SECRET_KEY="your-secret-key"
export AWS_DEFAULT_REGION="ap-northeast-2"

# Windows
set SECRET_KEY=your-secret-key
set AWS_DEFAULT_REGION=ap-northeast-2
```

5. 애플리케이션 실행
```bash
python run.py
```

6. 웹 브라우저에서 `http://localhost:5000` 접속

## 사용 방법 (Usage)

1. 로그인
   - 기본 계정으로 로그인: 사용자 이름 `admin`, 비밀번호 `admin`
   - AWS 액세스 키 ID와 시크릿 액세스 키 입력

2. 대시보드 사용
   - 통합 대시보드에서 전체 서비스 현황 확인
   - 서비스별 상세 정보 확인
   - 실시간 모니터링 데이터 확인

3. 추천 사항 확인
   - 서비스별 최적화 추천 사항 검토
   - 위험도별 필터링
   - 상세 개선 방안 확인
   - 추천 사항 조건에 대한 자세한 내용은 [recommendation_conditions.md](/static/docs/recommendation_conditions.md) 참조

## 보안 참고 사항 (Security Notes)

- AWS 자격 증명은 세션에만 저장되며 데이터베이스에 저장되지 않습니다.
- 모든 통신은 HTTPS를 통해 암호화됩니다.
- 프로덕션 환경에서는 다음 보안 조치를 권장합니다:
  - 기본 계정 정보 변경
  - 강력한 비밀번호 정책 적용
  - IP 기반 접근 제한
  - AWS IAM 역할 사용

## 개발 (Development)

- 이슈 트래커를 통한 버그 리포트 및 기능 요청
- 풀 리퀘스트 환영
- 코드 스타일: PEP 8 준수

## 프로젝트 구조 (Project Structure)

```
.
├── app/                    # 애플리케이션 패키지
│   ├── __init__.py         # 앱 초기화
│   ├── models/             # 데이터 모델
│   ├── routes/             # 라우트 정의
│   └── services/           # 서비스 로직
├── config.py               # 설정 파일
├── requirements.txt        # 의존성 목록
├── run.py                  # 애플리케이션 실행 스크립트
├── static/                 # 정적 파일 (CSS, JS)
│   ├── css/                # CSS 파일
│   └── js/                 # JavaScript 파일
└── templates/              # HTML 템플릿
    ├── base.html           # 기본 템플릿
    ├── consolidated.html   # 통합 대시보드 템플릿
    ├── recommendations.html# 추천 사항 템플릿
    └── login.html          # 로그인 템플릿
```

## 버전 관리 (Version Control)

이 프로젝트는 Git을 사용하여 버전 관리됩니다. `.gitignore` 파일이 포함되어 있어 다음과 같은 파일들은 버전 관리에서 제외됩니다:

- Python 캐시 파일 (`__pycache__/`, `*.pyc`)
- 가상 환경 디렉토리 (`venv/`, `env/`)
- 환경 변수 파일 (`.env`)
- IDE 설정 파일 (`.vscode/`, `.idea/`)
- 로그 파일 (`*.log`)
- 데이터베이스 파일 (`*.db`, `*.sqlite`)
- 테스트 캐시 및 커버리지 파일 (`.pytest_cache/`, `.coverage`)
- 민감한 인증 정보 (`credentials.json`, `*.pem`, `*.key`)
