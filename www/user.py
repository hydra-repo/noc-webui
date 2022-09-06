from flask import Blueprint, render_template, abort, request, redirect, url_for, Response, current_app
from jinja2 import TemplateNotFound
from functools import wraps
import hashlib
from bson.objectid import ObjectId

user = Blueprint('user', __name__, template_folder='templates')

from . import auth

from flask_wtf import Form
from wtforms import Form, BooleanField, StringField, PasswordField, SubmitField, HiddenField, TextAreaField, validators
from wtforms.validators import InputRequired, Email, EqualTo, ValidationError
from passlib.hash import pbkdf2_sha256

class UserForm(Form):
    id          = HiddenField(label="", id="_id", name="_id")
    email        = StringField('Email (will be username)', [InputRequired(), Email()])
    passw        = PasswordField('New Password', [EqualTo('passw2', message='Passwords must match')])
    passw2       = PasswordField('Confirm Password')
    name         = StringField('Name', [InputRequired()])
    namespace    = StringField('Namespace', [InputRequired()])
    is_noc_admin = BooleanField('Is user a NOC admin?', [])
    is_ns_admin  = BooleanField('Is user a namespace admin (can delegate)?', [])

    def validate_email(form, field):
        user = current_app.mongo.db.users.find_one({'email': field.data})
        if user and (not form.id.data or user['_id'] != ObjectId(form.id.data)):
            raise ValidationError('User with this email/username already exists')

    def validate_passw(form, field):
        if not form.id.data and form.passw.data == '':
            raise ValidationError('Password must be specified')

class User(dict):
    def getlist(self, key):
        return [self[key]]

    def __repr__(self):
        return type(self).__name__ + '(' + dict.__repr__(self) + ')'

@user.route('/users', methods = ['GET'], strict_slashes=False)
@auth.requires_auth
def list():
    users = current_app.mongo.db.users.find({ '$query': {}, '$orderby': { 'name' : 1 } })
    return render_template('user-list.html',
                           users=users, title="List of registered Hydra users")

@user.route('/users/add', methods = ['GET', 'POST'], strict_slashes=False)
@auth.requires_auth
def add():
    form = UserForm(request.form)
    if request.method == 'POST' and form.validate():

        keys = set(form.data.keys()) - set(['passw', 'passw2'])
        user = {key: form.data[key] for key in keys}
        user['password'] = pbkdf2_sha256.hash(form.data['passw'])

        current_app.mongo.db.users.insert_one(user)
        return redirect(url_for('user.list'))
    return render_template('add-or-edit.html', form=form, title="Add Hydra user")


@user.route('/users/edit/<id>', methods = ['GET', 'POST'], strict_slashes=False)
@auth.requires_auth
def edit(id):
    if request.method == 'POST':
        form = UserForm(request.form)
    else:
        user = current_app.mongo.db.users.find_one({'_id': ObjectId(id)})
        form = UserForm(User(user))

    if request.method == 'POST' and form.validate():

        keys = set(form.data.keys()) - set(['passw', 'passw2'])
        user = {key: form.data[key] for key in keys}

        if (form.data['passw'] != ''):
            user['password'] = pbkdf2_sha256.hash(form.data['passw'])

        current_app.mongo.db.users.update_one({'_id': ObjectId(id)},
                                              {'$set': user}, upsert=False)

        return redirect(url_for('user.list'))

    return render_template('add-or-edit.html', form=form,
                           title="Edit Hydra user")

@user.route('/users/delete/<id>', methods = ['GET', 'POST'], strict_slashes=False)
@auth.requires_auth
def delete(id):
    current_app.mongo.db.users.delete_one({'_id': ObjectId(id)})
    return redirect(url_for('user.list'))
