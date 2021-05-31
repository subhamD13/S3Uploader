from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import logging
import boto3
import mimetypes

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

app = Flask(__name__)

# secret key for encoding the token.
app.config['SECRET_KEY'] = 'thisissecretkey'
# PATH of login DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/subhamsaha/Desktop/perspect_drive/login.db'
db = SQLAlchemy(app)

# Credentials to access AWS S3 service
BUCKET_NAME = <bucket_name>
# Keep these credentials inside ~/.aws/config
# [default]
# region=us-east-1

# Keep these credentials inside ~/.aws/credentials boto3 automatically capture them.
# [default]
# aws_access_key_id = <aws_access_key_id>
# aws_secret_access_key = <aws_secret_access_key>

# User data model created for login/signin admin privilage.
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

# this function helps to Authenticate users.
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        LOGGER.info("here")
        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms="HS256")
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

# All admin has the privilege to see all the user details.
@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users' : output})

# All admin has the privilege to see a user details using the unique <public-id>.
@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})

# To signin user can use this route, it will not authenticate user. [Public API]
@app.route('/user', methods=['POST'])
def create_user():

    users = User.query.all()

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    # Assumption: First user will be admin by default.
    if not users:
        new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=True)
    else:
        new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New user created!'})

# To promote user to get admin privilege. Only admin can do this.
@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'The user has been promoted!'})

# To delete the existing user. Only admin can do this.
@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'The user has been deleted!'})

# To login existing user can use this route, it will HTTP basic authentication. [Public API]
@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({'token' : token})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

# List all objects/files of the specific user.
@app.route('/file', methods=['GET'])
@token_required
def list_file(current_user):
    directory_name = f"{current_user.public_id}/"

    s3 = boto3.client('s3')
    res = s3.list_objects(Bucket=BUCKET_NAME,Prefix=directory_name)

    output_list = []
    for content in res['Contents']:
        output_list.append(content['Key'])
    
    return jsonify({'objects' : output_list})

# Generate presigned URL to upload file securely.
def generate_presigned_upload_url(object_name, content_type, time_to_expire = 600):
    """
    Function to generate a presigned upload url to s3.
    Returns:
        str: presigned url
    """
    client = boto3.client('s3')
    url = client.generate_presigned_url(
        "put_object",
        Params={
            "Bucket": BUCKET_NAME,
            "Key": object_name,
            "ContentType": content_type,
        },
        ExpiresIn=time_to_expire,
    )
    return url

# Upload file securely.
@app.route('/file-upload/<file_name>', methods=['GET'])
@token_required
def upload_file(current_user, file_name):
    content_type = mimetypes.guess_type(file_name)[0]
    time_to_expire = 600
    upload_file_path = f"{current_user.public_id}/{file_name}"
    try:
        presigned_upload_url = generate_presigned_upload_url(
            object_name=upload_file_path,
            time_to_expire=time_to_expire,
            content_type=content_type,
        )
        output = {
                    "upload": {
                        "url": presigned_upload_url,
                        "expire_in": time_to_expire,
                    },
                    "file_name": file_name,
                }
        return jsonify({"upload_details": output})
    except:
        return jsonify({"message": "Internal server error"}), 500

# Delete existing file using file_path.
@app.route('/file', methods=['DELETE'])
@token_required
def delete_file(current_user):
    try:
        data = request.get_json()
        file_path = f"{current_user.public_id}/{data['file_path']}"

        s3 = boto3.client('s3')
        s3.delete_object(Bucket=BUCKET_NAME, Key=file_path)
        
        return jsonify({'message' : 'File is deleted!'})
    except:
        return jsonify({'message' : 'File is not found!'}), 404

# Create folder giving folder path.
@app.route('/folder', methods=['POST'])
@token_required
def create_folder(current_user):
    data = request.get_json()
    directory_name = f"{current_user.public_id}/{data['folder']}/"

    s3 = boto3.client('s3')
    s3.put_object(Bucket=BUCKET_NAME, Key=directory_name)

    return jsonify({'message' : 'New folder created!'})

# Delete existing folder using folder_path.
@app.route('/folder', methods=['DELETE'])
@token_required
def delete_folder(current_user):
    try:
        data = request.get_json()
        directory_name = f"{current_user.public_id}/{data['folder']}/"

        s3 = boto3.client('s3')
        s3.delete_object(Bucket=BUCKET_NAME, Key=directory_name)

        return jsonify({'message' : 'Folder is deleted!'})
    except:
        return jsonify({'message' : 'Folder is not found!'}), 404

if __name__ == '__main__':
    app.run(debug=True)