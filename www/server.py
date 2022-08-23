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
app.register_blueprint(node)
app.register_blueprint(user)

#############################################################################################
# User-facing components
#############################################################################################

@app.route('/', methods = ['GET'])
@app.route('/', methods = ['GET', 'POST'])
def index():
    return render_template('how-it-works.html')

#############################################################################################
# Operator-facing components
#############################################################################################

@app.route('/cert-requests/get/', methods = ['POST'])
def get_candidates():
    commandInterestName = ndn.Name()
    commandInterestName.wireDecode(
        # ndn.Blob(buffer(base64.b64decode(request.form['commandInterest']))))
        ndn.Blob(base64.b64decode(request.form['commandInterest'])))

    site_prefix = ndn.Name()
    site_prefix.wireDecode(commandInterestName[-3].getValue().toBuffer())
    timestamp  = commandInterestName[-4]

    signature = ndn.WireFormat.getDefaultWireFormat().decodeSignatureInfoAndValue(commandInterestName[-2].getValue().toBuffer(),
                                                                                  commandInterestName[-1].getValue().toBuffer())
    keyLocator = signature.getKeyLocator().getKeyName()

    operator = mongo.db.operators.find_one({'site_prefix': site_prefix.toUri()})
    if operator == None:
        abort(403)

    try:
        keyChain = KeyChain(policyManager = OperatorVerifyPolicyManager(operator))

        def onVerified(interest):
            pass

        def onVerifyFailed(interest):
            raise RuntimeError("Operator verification failed")

        keyChain.verifyInterest(ndn.Interest(commandInterestName), onVerified, onVerifyFailed, stepCount=1)
    except Exception as e:
        print("ERROR: %s" % e)
        abort(403)

    # Will get here if verification succeeds
    requests = mongo.db.requests.find({'operator_id': str(operator['_id'])})
    output = []
    for req in requests:
        output.append(req)

    return json.dumps(output, default=json_util.default)

@app.route('/cert/submit/', methods = ['POST'])
def submit_certificate():
    data = ndn.Data()
    # data.wireDecode(ndn.Blob(buffer(base64.b64decode(request.form['data']))))
    data.wireDecode(ndn.Blob(memoryview(base64.b64decode(request.form['data']))))

    cert_request = mongo.db.requests.find_one({'_id': ObjectId(str(request.form['id']))})
    if cert_request == None:
        abort(403)

        operator = mongo.db.operators.find_one({"_id": ObjectId(cert_request['operator_id'])})
    if operator == None:
        mongo.db.requests.remove(cert_request) # remove invalid request
        abort(403)

    # # @todo verify data packet
    # # @todo verify timestamp

    if len(data.getContent()) == 0:
        # (no deny reason for now)
        # eventually, need to check data.type: if NACK, then content contains reason for denial
        #                                      if KEY, then content is the certificate

        msg = Message("[NDN Certification] Rejected certification",
                      sender = app.config['MAIL_FROM'],
                      recipients = [cert_request['email']],
                      body = render_template('cert-rejected-email.txt',
                                             URL=app.config['URL'], **cert_request),
                      html = render_template('cert-rejected-email.html',
                                             URL=app.config['URL'], **cert_request))
        mail.send(msg)

        mongo.db.requests.remove(cert_request)

        return "OK. Certificate has been denied"
    else:
        cert = {
            'name': data.getName().toUri(),
            'cert': request.form['data'],
            'operator': operator,
            'created_on': datetime.datetime.utcnow(), # to periodically remove unverified tokens
            }
        mongo.db.certs.insert(cert)

        msg = Message("[NDN Certification] NDN certificate issued",
                      sender = app.config['MAIL_FROM'],
                      recipients = [cert_request['email']],
                      body = render_template('cert-issued-email.txt',
                                             URL=app.config['URL'],
                                             quoted_cert_name=urllib.parse.quote(cert['name'], ''),
                                             cert_id=str(data.getName()[-3]),
                                             **cert_request),
                      html = render_template('cert-issued-email.html',
                                             URL=app.config['URL'],
                                             quoted_cert_name=urllib.parse.quote(cert['name'], ''),
                                             cert_id=str(data.getName()[-3]),
                                             **cert_request))
        mail.send(msg)

        mongo.db.requests.remove(cert_request)

        return "OK. Certificate has been approved and notification sent to the requester"

#############################################################################################
# Helpers
#############################################################################################

def generate_token():
    return ''.join([random.choice(string.ascii_letters + string.digits) for n in range(60)])

def ndnify(dnsName):
    ndnName = ndn.Name()
    for component in reversed(dnsName.split(".")):
        ndnName = ndnName.append(str(component))
    return ndnName

def get_operator_for_email(email):
    # very basic pre-validation
    user, domain = email.split('@', 2)
    operator = mongo.db.operators.find_one({'site_emails': {'$in':[ domain ]}})
    if (operator == None):
        operator = mongo.db.operators.find_one({'site_emails': {'$in':[ 'guest' ]}})

        if (operator == None):
            raise Exception("Unknown site for domain [%s]" % domain)

        # Special handling for guests
        ndn_domain = ndn.Name("/ndn/guest")
        assigned_namespace = ndn.Name('/ndn/guest')
        assigned_namespace.append(str(email))
    else:
        if domain == "operators.named-data.net":
            ndn_domain = ndn.Name(str(user))
            assigned_namespace = ndn.Name(str(user))
        else:
            ndn_domain = ndnify(domain)
            assigned_namespace = ndn.Name('/ndn')
            assigned_namespace \
                .append(ndn_domain) \
                .append(str(user))

    # return various things
    return {'operator':operator, 'user':user, 'domain':domain, 'requestDetails':True,
            'ndn_domain':ndn_domain, 'assigned_namespace':assigned_namespace}

def get_operator_for_guest_site(email, site_prefix):
    operator = mongo.db.operators.find_one({'site_prefix': site_prefix, 'allowGuests': True})
    if (operator == None):
        raise Exception("Invalid site")

    assigned_namespace = ndn.Name(site_prefix)
    assigned_namespace \
      .append("@GUEST") \
      .append(email)

    # return various things
    return {'operator':operator, 'user':None, 'domain':None, 'requestDetails':False,
            'ndn_domain':site_prefix, 'assigned_namespace':assigned_namespace}

if __name__ == '__main__':
    app.run(debug = True, host='0.0.0.0')
