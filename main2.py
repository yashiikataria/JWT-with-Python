from flask import Flask,request,jsonify,make_response,render_template,session
import jwt
import uuid
from werkzeug.security import generate_password_hash,check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime,timedelta
from functools import wraps
app=Flask(__name__)
app.config['SECRET_KEY']='5b3bfeff336e4a47b8af1db698b27bbb'
# secret_key = app.config['SECRET_KEY']
# print(f"Secret Key: {secret_key}")
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///todo.db'
db=SQLAlchemy(app)

# DATABASES- USER AND TODOs
class User(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    public_id=db.Column(db.String(50),unique=True)
    name=db.Column(db.String(50))
    password=db.Column(db.String(80))
    admin=db.Column(db.Boolean)
class Todo(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    text=db.Column(db.String(50))
    complete=db.Column(db.Boolean)
    user_id=db.Column(db.Integer)

# JWT VALDATION
def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token=None
        if 'x-access-token' in request.headers:
            token=request.headers['x-access-token']
        if not token:
            return jsonify({'message':"invalid token"})
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user=User.query.filter_by(public_id=data['public_id']).first()
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        except Exception as e:
            return jsonify({'message': 'An error occurred', 'error': str(e)}), 401
        except:
            return jsonify({'message':'token is invalid'}),401
        return f(current_user,*args,**kwargs)
    return decorated


# USER API
@app.route('/user',methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message':"cannot perform this function"})
    users=User.query.all()
    output=[]
    for user in users:
        user_data={}
        user_data['public_id']=user.public_id
        user_data['name']=user.name
        user_data['password']=user.password
        user_data['admin']=user.admin
        output.append(user_data)
    # if 'text/html' in request.accept_mimetypes:
    #     return render_template("login.html")
    # else:
    #     return jsonify({'users': output})
    return jsonify({'users':output})
    # return render_template("login.html",text="Testing",user="yashika")


@app.route('/user/<public_id>',methods=['GET'])
@token_required
def get_one_user(current_user,public_id):
    if not current_user.admin:
        return jsonify({'message':"cannot perform this function"})
    user=User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message':"no user found"})
    user_data={}
    user_data['public_id']=user.public_id
    user_data['name']=user.name
    user_data['password']=user.password
    user_data['admin']=user.admin
    return jsonify({'user':user_data})


@app.route('/user',methods=['POST'])
# @token_required
def create_user():
    # if not current_user.admin:
    #     return jsonify({'message':"cannot perform this function"})
    data=request.get_json()
    hashed_password=generate_password_hash(data['password'],method='sha256')
    new_user=User(public_id=str(uuid.uuid4()),name=data['name'], password=hashed_password,admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message':'new user created'})


@app.route('/user/<public_id>',methods=['PUT'])
@token_required
def promote_user(current_user,public_id):
    if not current_user.admin:
        return jsonify({'message':"cannot perform this function"})
    user=User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message':'no user found'})
    user.admin=True
    db.session.commit()
    return jsonify({'message':'the user has been updated'})


@app.route('/user/<public_id>',methods=['DELETE'])
@token_required
def delete_user(current_user,public_id):
    if not current_user.admin:
        return jsonify({'message':"cannot perform this function"})
    user=User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message':'no user found'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message':"user deleted"})

# FOR LOGGIN IN
@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'WWW-Autheticate': 'Basic realm="Login required"'})
    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('could not verify', 401, {'WWW-Autheticate': 'Basic realm="Login required"'})
    if check_password_hash(user.password, auth.password):
        # secret_key = app.config['SECRET_KEY']
        # print(f"Secret Key: {secret_key}")
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.utcnow() + timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token': token})
    return make_response('could not verify', 401, {'WWW-Autheticate': 'Basic realm="Login required"'})
   


# TODOs  API
@app.route('/todo',methods=['GET'])
@token_required
def get_all_todos(current_user):
    todos=Todo.query.filter_by(user_id=current_user.id).all()
    output=[]
    for todo in todos:
        todo_data={}
        todo_data['id']=todo.id
        todo_data['text']=todo.text
        todo_data['complete']=todo.complete
        output.append(todo_data)
    return jsonify({'todos':output})

@app.route('/todo/<todo_id>',methods=['GET'])
@token_required
def get_one_todo(current_user,todo_id):
    todo=Todo.query.filter_by(id=todo_id,user_id=current_user.id).first()
    if not todo:
        return jsonify({
            'message':'no todo found'
        })
    todo_data={}
    todo_data['id']=todo.id
    todo_data['text']=todo.text
    todo_data['complete']=todo.complete
    
    return jsonify({'message':'requested todo'},todo_data)

@app.route('/todo',methods=['POST'])
@token_required
def create_todo(current_user):
    data=request.get_json()
    new_todo=Todo(text=data['text'],complete=False,user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()
    return jsonify({'message':"Todo created"})

@app.route('/todo/<todo_id>',methods=['PUT'])
@token_required
def complete_todo(current_user,todo_id):
    todo=Todo.query.filter_by(id=todo_id,user_id=current_user.id).first()
    if not todo:
        return jsonify({'message':'no todo found!'})
    todo.complete=True
    db.session.commit()
    return jsonify({'message':'todo item has been completed'})

@app.route('/todo/<todo_id>',methods=['DELETE'])
@token_required
def delete_todo(current_user,todo_id):
    todo=Todo.query.filter_by(id=todo_id,user_id=current_user.id).first()
    if not todo:
        return jsonify({'message':'no todo found!'})
    db.session.delete(todo)
    db.session.commit()
    return jsonify({'message':'todo item deleted'})



if __name__=="__main__":
    with app.app_context():
       db.create_all()
    app.run(debug=True)