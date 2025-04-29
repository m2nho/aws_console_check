import os
from app import app

if __name__ == '__main__':
    # 템플릿 디렉토리가 없으면 생성
    if not os.path.exists('templates'):
        os.makedirs('templates')
    # 정적 파일 디렉토리가 없으면 생성
    if not os.path.exists('static'):
        os.makedirs('static')
    
    app.run(debug=True)