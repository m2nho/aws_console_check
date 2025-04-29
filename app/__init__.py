from flask import Flask
from flask_login import LoginManager
from config import Config

# 앱 초기화
app = Flask(__name__, template_folder='../templates', static_folder='../static')
app.config.from_object(Config)

# 로그인 매니저 설정
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = '이 페이지에 접근하려면 로그인이 필요합니다.'

# 모듈 임포트 (순환 임포트 방지를 위해 여기서 임포트)
from app.models.user import User
from app.routes.auth import login, logout
from app.routes.main import index
from app.routes.dashboard import consolidated_view
from app.routes.recommendations import recommendations_view

# 사용자 로더 설정
from app.models.user import load_user