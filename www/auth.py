from flask_login import login_user, logout_user, LoginManager

from flask import Blueprint, render_template, abort, request, redirect, url_for, Response, current_app
from jinja2 import TemplateNotFound
from functools import wraps
from passlib.hash import pbkdf2_sha256

auth = Blueprint('auth', __name__, template_folder='templates')

@auth.route('/logout', methods = ['GET'], strict_slashes=False)
def reset_auth():
    logout_user()
    request.authorization = None
    return redirect(url_for('index'))


def check_auth(username, password, level):
    """This function is called to check if a username /
    password combination is valid.
    """

    # Remove INIT_AUTH after initial user configuration
    try:
        if current_app.config['INIT_AUTH']:
            return True
    except:
        pass

    # current_app.mongo.db.users.find_one({'email': field.data})
    user = current_app.mongo.db.users.find_one({'email': username})
    if not user:
        return False

    if level == 'noc_admin' and not user['is_no_admin']:
        return False

    if level == 'ns_admin' and not user['is_ns_admin']:
        return False

    return pbkdf2_sha256.verify(password, user['password'])

def authenticate(level):
    """Sends a 401 response that enables basic auth"""
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f, level='user'):

    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password, level):
            return authenticate(level)
        return f(*args, **kwargs)

    return decorated


