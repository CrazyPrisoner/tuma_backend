# -*- coding: utf-8 -*-

from flask import Flask, jsonify, request, jsonify, render_template, redirect
from flask_mail import Mail, Message
import hashlib
import json
from bson import json_util
from bson.json_util import dumps
from flask_pymongo import PyMongo 
from bson.objectid import ObjectId 
from datetime import datetime 
from flask_cors import CORS 
from flask_bcrypt import Bcrypt 
from flask_jwt_extended import JWTManager
from flask_jwt_extended import create_access_token

app = Flask(__name__)

app.config['MONGO_DBNAME'] = 'test'
app.config['MONGO_URI'] = 'mongodb://localhost:27019/test'
app.config['JWT_SECRET_KEY'] = 'secret'
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'w.repeinik@gmail.com'  # enter your email here
app.config['MAIL_DEFAULT_SENDER'] = 'w.repeinik@gmail.com' # enter your email here
app.config['MAIL_PASSWORD'] = 'workshiper191173R' # enter your password here

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
mail = Mail(app)

CORS(app)

def send_mail_smtp(recipient, name, link):
    msg = Message(subject="Confirm your email", sender=app.config['MAIL_DEFAULT_SENDER'], recipients = [recipient])
    msg.html = render_template('form.html', name=name, link=link)
    mail.send(msg)
    result = jsonify({'mail' : 'send'})
    
    return result

# Users
@app.route('/user/register', methods=['POST'])
def register():
    users = mongo.db.users
    last_user = users.find().count()
    data = request.get_json()
    data['_id'] = int(last_user) + 1
    data['password'] = bcrypt.generate_password_hash(request.get_json()['password']).decode('utf-8')
    data['created'] = datetime.utcnow()
    data['active'] = False
    data['admin'] = False
    data['edited'] = None
    all_users = users.find().count()
    user_id = users.insert(data)
    # SMTP
    new_user = users.find_one({'_id': user_id})
    link = "192.168.1.2:5000/user/confirm/" + str(user_id)
    result_smtp = send_mail_smtp(recipient = new_user['email'], name = new_user['name'], link=link)
    result = jsonify({'email': new_user['email'] + ' registered'})
    
    return result

@app.route('/user/login', methods=['POST'])
def login():
    users = mongo.db.users 
    email = request.get_json()['email']
    password = request.get_json()['password']
    result = ""

    response = users.find_one({'email': email})

    if response:
        if bcrypt.check_password_hash(response['password'], password):
            access_token = create_access_token(identity = {
                'name': response['name'],
                'email': response['email']
            })
            result = jsonify({"token": access_token,
                              "id" : response['_id'],
                              "admin" : response['admin'],
                              "active" : response['active']})
        else:
            result = jsonify({"error": "Invalid name and password"})
    else:
        result = jsonify({"result": "No results found"})
    return result

@app.route('/user/<int:id>', methods=['GET'])
def get_user(id):
    users = mongo.db.users
    result = jsonify(users.find_one({'_id' : id}))

    return result

@app.route('/users', methods=['GET'])
def get_all_users():
    users = mongo.db.users
    result = jsonify([user for user in users.find()])
    print(result)

    return result

@app.route('/user/<int:id>', methods=['PUT'])
def edit_user(id):
    users = mongo.db.users
    data = request.get_json()
    user = users.find_one({'email': data['email']})
    if (id == 0 or users.find_one({'_id' : id})['_id'] != id):
        result = jsonify({'user' : 'not found'})
    elif ("OldPassword" in data):
        if (bcrypt.check_password_hash(user['password'], data['OldPassword'])):
            data['password'] = bcrypt.generate_password_hash(data['NewPassword']).decode('utf-8')
            del data['OldPassword']
            del data['NewPassword']
            users.find_one_and_update({'_id' : id}, {'$set' : data})
            result = jsonify({'user' : 'updated'})
        else:
            result = jsonify({'user' : 'wrong password'})
    else:
        users.find_one_and_update({'_id' : id}, {'$set' : data})
        result = jsonify({'user' : 'updated'})

    return result

@app.route('/user/<int:id>', methods=['DELETE'])
def delete_user(id):
    users = mongo.db.users
    users.remove({'_id' : id})
    result = jsonify({'user' : 'deleted'})

    return result

# Category
@app.route('/category', methods=['POST'])
def add_category():
    category = mongo.db.category
    all_categories_count = category.count()
    title = request.get_json()['title']
    if all_categories_count == 0:
        category.insert({
            '_id' :  1,
            'title' : title
        })
        result = jsonify({'category' : 'created'})

    else:
        category.insert({
            '_id' : all_categories_count + 1,
            'title' : title
        })
        result = jsonify({'category' : 'added'})

    return result

@app.route('/categories', methods=['GET'])
def get_all_categories():
    category = mongo.db.category
    result = [item for item in category.find()]
    
    return jsonify(result)


@app.route('/category/<int:id>', methods=['GET'])
def get_one_category(id):
    category = mongo.db.category
    all_categories_count = category.find().count()
    if (id == 0 or category.find_one({'_id' : id})['_id'] != id):
        result = jsonify({'category' : 'ERROR'})
    else:
        category_item = category.find_one({'_id' : id})
        result = category_item

    return result

@app.route('/category/<int:id>', methods=['PUT'])
def edit_category(id):
    category = mongo.db.category
    category_count = category.find().count()
    if (id == 0 or category.find_one({'_id' : id})['_id'] != id):
        result = jsonify({'category' : 'ERROR'})
    else:
        category.find_one_and_update({'_id' : id}, {'$set' : request.get_json()})
        result = jsonify({'category' : 'updated'})

    return result

@app.route('/category/<int:id>', methods=['DELETE'])
def delete_category(id):
    category = mongo.db.category
    category_count = category.find().count()
    if (id == 0 or category.find_one({'_id' : id})['_id'] != id):
        result = jsonify({'category' : 'ERROR'})
    else:
        category.remove({'_id' : id})
        result = jsonify({'category' : 'deleted'})

    return result

# Products
@app.route('/product', methods=['POST'])
def add_product():
    product = mongo.db.product
    all_products_count = product.find().count()
    data = request.get_json()
    if (all_products_count == 0):
        data['_id'] =  1
        product.insert(data)
        result = jsonify({'product' : 'created'})
    else:
        data['_id'] = all_products_count + 1
        product.insert(data)
        result = jsonify({'product' : 'added'})

    return result

@app.route('/products', methods=['GET'])
def get_all_products():
    product = mongo.db.product
    result = jsonify([item for item in product.find()])
    
    return result

@app.route('/product/<int:id>', methods=['GET'])
def get_one_product(id):
    product = mongo.db.product
    all_products_count = product.find().count()
    if (id == 0 or product.find_one({'_id' : id})['_id'] != id):
        result = jsonify({'product' : 'ERROR'})
    else:
        product_item = product.find_one({'_id' : id})
        result = jsonify(product_item)

    return result

@app.route('/product/<int:id>', methods=['PUT'])
def edit_product(id):
    product = mongo.db.product
    all_products = product.find().count()
    print(request.get_json())
    if (id == 0 or product.find_one({'_id' : id})['_id'] != id):
        result = jsonify({'product' : 'ERROR'})
    else:
        product.find_one_and_update({'_id' : id}, {'$set' : request.get_json()})
        result = jsonify({'product' : 'updated'})
    
    return result

@app.route('/product/<int:id>', methods=['DELETE'])
def delete_product(id):
    product = mongo.db.product
    product.remove({'_id' : id})
    result = jsonify({'product' : 'deleted'})

    return result

# Cart
@app.route('/cart/<int:id>', methods=['PUT'])
def edit_items(id):
    cart = mongo.db.cart
    users = mongo.db.users
    data = {'_id' : id,
            'UserProducts' : request.get_json()}
    print(data)
    if (users.find_one({'_id' : id})['_id'] != id):
        result = jsonify({'cart' : 'ERROR (cart not found)'})
    elif (cart.find_one({'_id' : id}) == None or cart.find_one({'_id' : id}) == 0):
        data['_id'] = int(id)
        cart.insert(data)
        result = jsonify({'cart' : 'created'})
    else:
        cart.find_one_and_update({'_id' : id}, {'$set' : request.get_json()})
        result = jsonify({'cart' : 'updated'})

    return result

@app.route('/cart/<int:id>', methods=['GET'])
def get_all_items(id):
    cart = mongo.db.cart
    user_cart = cart.find_one({'_id' : id})
    result = jsonify(user_cart)
    
    return result

@app.route('/carts', methods=['GET'])
def get_all_carts():
    cart = mongo.db.cart
    result = jsonify([item for item in cart.find()])
    
    return result

@app.route('/user/confirm/<int:id>', methods=['GET'])
def smtp_confirm(id):
    users = mongo.db.users
    users.find_one_and_update({'_id' : id}, {'$set' : {'active' : True}})
    result = jsonify({'email' : 'confirmed'})
    return redirect("http://192.168.1.7:8080/login")

@app.route('/user/admin', methods=['POST'])
def create_admin():
    users = mongo.db.users
    users.insert(request.get_json())
    result = jsonify({'admin' : 'created'})

    return result

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)