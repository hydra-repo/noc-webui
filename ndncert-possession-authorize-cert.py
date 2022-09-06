#!/usr/bin/env python3

#html/rest
from flask import Flask, jsonify, abort
from flask_pymongo import PyMongo

from bson import json_util
from bson.objectid import ObjectId

import sys
import os

tmpl_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'www/templates')

# name of app is also name of mongodb "database"
app = Flask("hydra-noc",
            template_folder=tmpl_dir)
app.config.from_pyfile('%s/www/settings.py' % os.path.dirname(os.path.abspath(__file__)))
mongo = PyMongo(app)


def authorize_cert(namespace, cert):
    node = mongo.db.nodes.find_one({'node_prefix': namespace})
    if not node:
        return False

    import re
    cert1 = re.sub(r"\s+", "", cert)
    cert2 = re.sub("\s+", "", node['key'])

    print ("Supplied cert:  %s" % cert1[0:100])
    print ("Cert in the db: %s" % cert2[0:100])
    return cert1 == cert2

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: ./ndncert-possession-authorize-cert.py [NODE_IDENTITY] [NODE_CERT_BASE64]")
        sys.exit(2)
    
    authOk = authorize_cert(sys.argv[1], sys.argv[2])

    if authOk:
        sys.exit(0)
    else:
        sys.exit(1)
