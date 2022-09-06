#!/usr/bin/env python3

# Copyright (c) 2014  Regents of the University of California
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# dependencies - flask, flask-pymongo
# pip install Flask, Flask-PyMongo

#html/rest
from flask import Flask, jsonify, abort, make_response, request, render_template
from flask_pymongo import PyMongo
from flask_login import login_user, logout_user, LoginManager

import os
import string
import random
import datetime
import base64

import json
import urllib.parse

from bson import json_util
from bson.objectid import ObjectId

from ndn.encoding import Name, Component

tmpl_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')

# name of app is also name of mongodb "database"
app = Flask("hydra-noc",
            template_folder=tmpl_dir,
            static_folder="assets",
            static_url_path="/assets")
app.config.from_pyfile('%s/settings.py' % os.path.dirname(os.path.abspath(__file__)))
mongo = PyMongo(app)

app.mongo = mongo

from .node import node
from .user import user
from .auth import auth
app.register_blueprint(node)
app.register_blueprint(user)
app.register_blueprint(auth)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(username):
    return app.mongo.db.users.find_one({'email': username})


#############################################################################################
# User-facing components
#############################################################################################

@app.route('/', methods = ['GET'])
@app.route('/', methods = ['GET', 'POST'])
def index():
    return render_template('how-it-works.html')

if __name__ == '__main__':
    app.run(debug = True, host='0.0.0.0')
