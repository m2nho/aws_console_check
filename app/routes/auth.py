from flask import render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, current_user
from werkzeug.security import check_password_hash
from app import app
from app.models.user import users

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('consolidated_view'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        aws_access_key = request.form.get('aws_access_key')
        aws_secret_key = request.form.get('aws_secret_key')
        
        # 사용자 인증
        user = next((u for u in users.values() if u.username == username), None)
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            
            # AWS 자격 증명 저장
            session['aws_access_key'] = aws_access_key
            session['aws_secret_key'] = aws_secret_key
            
            return redirect(url_for('consolidated_view'))
        else:
            flash('사용자 이름 또는 비밀번호가 올바르지 않습니다.')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    # AWS 자격 증명 제거
    session.pop('aws_access_key', None)
    session.pop('aws_secret_key', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('login'))