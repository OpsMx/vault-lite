#!/bin/python3
"""
Simple Sentinel API to front a standalone simple Sentinel service locally
inside a container, or reach out to Vault Enterprise for policy evaluation

"""
import sys
import os

from flask import Flask
from flask_cors import CORS
from flask_restplus import Api
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from routes.v1 import api as v1
import config

prefix_path = os.getenv("PREFIX_PATH", default="")
api_path = os.getenv("API_PATH", default="")
doc_path = os.getenv("DOC_PATH", default="/v1/doc")

if prefix_path != "" and not prefix_path.startswith("/") \
                     and not prefix_path.endswith("/") \
                     or prefix_path == "/":
    print("ERROR: PREFIX_PATH has to start with a '/', but can't end in '/'")
    sys.exit(1)
else:
    print("PREFIX_PATH: %s" % prefix_path)

if doc_path == "False":
    doc_path = False

APP = Flask(__name__)
# restrict CORS later...
CORS(APP, resources="/*")
APP.config["APPLICATION_ROOT"] = prefix_path
API = Api(APP,
          prefix=api_path,
          doc=doc_path,
          version=config.VERSION,
          title=config.TITLE,
          default=config.NAME,
          default_label=config.NAME_LABEL)
API.add_namespace(v1)

if prefix_path:
    APP.wsgi_app = DispatcherMiddleware(APP, {
        prefix_path: APP.wsgi_app,
        "": APP.wsgi_app
    })


if __name__ == '__main__':
    APP.run(debug=True, host="0.0.0.0", port=8200)
