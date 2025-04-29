from flask_login import UserMixin
from werkzeug.security import generate_password_hash
from app import login_manager

# 사용자 모델 (실제 프로젝트에서는 데이터베이스 사용 권장)
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password_hash = password

# 사용자 데이터 (실제 프로젝트에서는 데이터베이스 사용 권장)
users = {
    '1': User('1', 'admin', generate_password_hash('admin'))
}

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)