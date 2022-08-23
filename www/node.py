from flask import Blueprint, render_template, abort, request, redirect, url_for, Response, current_app
from jinja2 import TemplateNotFound
from functools import wraps
import hashlib
from bson.objectid import ObjectId

node = Blueprint('node', __name__, template_folder='templates')

from . import auth

from flask_wtf import Form
from wtforms import Form, BooleanField, StringField, SubmitField, HiddenField, TextAreaField, validators
from wtforms.validators import InputRequired

class NodeForm(Form):
    _id         = HiddenField()
    node_name   = StringField('Node Name', [InputRequired()])
    node_prefix = StringField('Assigned Hydra Prefix', [InputRequired()])
    key         = TextAreaField('Self-signed NDN cert of the Hydra node')

class Node(dict):
    def getlist(self, key):
        return [self[key]]

    def __repr__(self):
        return type(self).__name__ + '(' + dict.__repr__(self) + ')'

@node.route('/nodes', methods = ['GET'], strict_slashes=False)
@auth.requires_auth
def list():
    nodes = current_app.mongo.db.nodes.find({ '$query': {}, '$orderby': { 'node_prefix' : 1 } })
    return render_template('node-list.html',
                           nodes=nodes, title="List of registered Hydra nodes")

@node.route('/nodes/add', methods = ['GET', 'POST'], strict_slashes=False)
@auth.requires_auth
def add():
    form = NodeForm(request.form)
    if request.method == 'POST' and form.validate():
        node = form.data
        current_app.mongo.db.nodes.insert_one(node)
        return redirect(url_for('node.list'))
    return render_template('add-or-edit.html', form=form, title="Add Hydra node")


@node.route('/nodes/edit/<id>', methods = ['GET', 'POST'], strict_slashes=False)
@auth.requires_auth
def edit(id):
    if request.method == 'POST':
        form = NodeForm(request.form)
    else:
        node = current_app.mongo.db.nodes.find_one({'_id': ObjectId(id)})
        form = NodeForm(Node(node))

    if request.method == 'POST' and form.validate():

        node = form.data
        current_app.mongo.db.nodes.update_one({'_id': ObjectId(id)},
                                              {'$set': node}, upsert=False)

        return redirect(url_for('node.list'))

    return render_template('add-or-edit.html', form=form,
                           title="Edit Hydra node")

@node.route('/nodes/delete/<id>', methods = ['GET', 'POST'], strict_slashes=False)
@auth.requires_auth
def delete(id):
    current_app.mongo.db.nodes.delete_one({'_id': ObjectId(id)})
    return redirect(url_for('node.list'))
