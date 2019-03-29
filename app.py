import os
import json
from datetime import datetime
from datetime import timedelta
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user

from check_password import check_password

#init app
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'hot-wi-fi'


db = SQLAlchemy(app)
ma = Marshmallow(app)
login = LoginManager(app)
hash = generate_password_hash('hot-wi-fi')

#Account
class Account(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(20), unique=True)
    password_hash = db.Column(db.String(128))
    password_end = db.Column(db.DateTime, nullable=False,
        default=datetime.now() + timedelta(days=30) )


    def __init__(self, login, password):
        self.login =  login
        self.password_hash = generate_password_hash(password)


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class AccountSchema(ma.Schema):
    class Meta:
        fields = ('id', 'login', 'password_hash', 'password_end')

account_schema = AccountSchema(strict=True)
accounts_schema = AccountSchema(many = True, strict=True)

root = Account.query.filter_by(login="root").first()
if not root:
    superuser = Account("root", "root")
    db.session.add(superuser)
    db.session.commit()

#Create Account

@app.route('/api/accounts', methods=['POST'])
def add_account():
    if current_user.is_authenticated and current_user.login == "root":
        login = request.json['login']
        password = request.json['password']

        if check_password(password):
            new_account = Account(login, password)
            db.session.add(new_account)
            db.session.commit()
        else:
            return jsonify("Password does not satisfy the policy ")

        return account_schema.jsonify(new_account)
    else:
        return jsonify("You should have root rights to add accounts")

@app.route('/api/accounts/<id>/password', methods=['PUT'])
def change_password(id):
    oldPassword = request.json['oldPassword']
    newPassword = request.json['newPassword']

    if not check_password(newPassword):
        return jsonify("Password does not satisfy the policy ")


    account = Account.query.get(int(id))
    if account.check_password(oldPassword):
        account.set_password(newPassword)
    else:
        return jsonify("Inccorrect password")

    db.session.commit()
    return account_schema.jsonify(account)


@app.route('/api/accounts', methods=['GET'])
def get_accounts():
    all_accounts = Account.query.all()
    result = accounts_schema.dump(all_accounts)
    return jsonify(result.data)


@login.user_loader
def load_user(id):
    return Account.query.get(int(id))

@app.route('/api/accounts/login', methods=['POST'])
def login():

    if current_user.is_authenticated:
        return jsonify("You already authenticated, please logged out at first")
    else:

        login = request.json['login']
        password = request.json['password']
        account = Account.query.filter_by(login=login).first()

        if not account:
            result = "No such account"
            return jsonify(result)
        else:
            if not account.check_password(password):
                result = "Incorrect password"
                return jsonify(result)

        login_user(account)
        if account.password_end < datetime.now():
            result = "You successfully logged in, CHANGE your password, deadline is over!"
        else:
            result = "You successfully logged in"
        return jsonify(result)


@app.route('/api/accounts/logout', methods=['POST'])
def logout():
    logout_user()
    result = "You successfully logged out"
    return jsonify(result)


@app.route('/api/accounts/<id>', methods=['DELETE'])
def delete_account(id):
    if current_user.is_authenticated and current_user.login == "root":
        account = Account.query.get(int(id))
        if not account:
            return jsonify("Account not found")
        else:
            db.session.delete(account)
            result = "Account successfully deleted"
            return jsonify(result)
        return account_schema.jsonify(account)
    else:
        return jsonify("You should have root rights to delete accounts")


@app.route('/api/accounts/password/policy', methods=['GET'])
def get_policy():
    f = open("policy.json","r")
    data = f.read()
    return data

@app.route('/api/accounts/password/policy', methods=['POST'])
def change_policy():
    data = request.json
    print("DATA", data)
    # toDO 
    with open('policy.json', 'w') as outfile:
        json.dump(data, outfile)

    result = "Policy successfully changed"
    return jsonify(result)


if __name__ == '__main__':
    app.run(debug=True)
