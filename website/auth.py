from flask import Blueprint,render_template,request,flash,redirect,url_for,jsonify
auth=Blueprint('auth',__name__)
from .models import user,note
from werkzeug.security import generate_password_hash,check_password_hash
from . import db
from flask_login import login_user,login_required,logout_user,current_user
@auth.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
         email=request.form.get('email')
         password=request.form.get('password')
         User=user.query.filter_by(email=email).first()
         if User:
            if check_password_hash(User.password,password):
                flash('logged in successfully',category='success')
                login_user(User,remember=True)
            else:
                 flash('incorrect password',category='error')
         else:
            flash('Email does not exist',category='error')

    return render_template("login.html",text="Testing",user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
    

@auth.route('/signup',methods=['GET','POST'])
def signup():
           
           if request.method=='POST':
             
                email=request.form.get('email')
                first_name=request.form.get('firstname')
                password1=request.form.get('password1')
                password2=request.form.get('password2')
                User=user.query.filter_by(email=email).first()
                if User:
                     flash('email already exists',category='error')
                if len(email)<4:
                    flash('email must be greater than 4 characters',category='error')
                elif len(first_name)<2:
                    flash('email must be greater than 1 character',category='error')
                elif password1!=password2:
                    flash('Passwords dont match',category='error')
                elif len(password1)<7:
                    flash('Password must be atleast greater than 7 characters',category='error')
                else:
                    new_user = user(email=email, first_name=first_name, password=generate_password_hash(password1, method='sha256'))
                    db.session.add(new_user)
                    db.session.commit()
                    login_user(User,remember=True)
                    flash('account created',category='success')
                    return redirect(url_for('views.home'))

         
           return render_template("signup.html",user=current_user)
  
# @auth.route('/users', methods=['GET'])
# def get_users():
#     users = user.query.all()  # Fetch all users from the database
#     user_list = [{'email': u.email, 'first_name': u.first_name} for u in users]  # Convert users to a list of dictionaries
#     return jsonify({'users': user_list}), 200

        
   


