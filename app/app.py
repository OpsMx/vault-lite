#!/bin/python3
"""
Simple Sentinel API to front a standalone simple Sentinel service locally
inside a container, or reach out to Vault Enterprise for policy evaluation

TODO:
    .) Move file actions out of here
"""
import sys
import time
import json
import tempfile
import os
from flask import Flask, Blueprint, request, jsonify
from flask_cors import CORS
from flask_restplus import Resource, Api, fields
from libs import Sentinel
from libs import Models

VERSION = "0.1"
NAME = "vault-lite-api"
NAME_LABEL = "Vault-lite"
TITLE = "Swaggering ", NAME_LABEL
POLICY_DIR = "../policy"
TEMP_DIR = "/tmp"

APP = Flask(__name__)
# restrict CORS later...
CORS(APP, resources="/*")
API = Api(APP,
          doc='/doc/',
          version=VERSION,
          title=TITLE,
          default=NAME,
          default_label=NAME_LABEL)

DEBUG = True
APP.config["DEBUG"] = DEBUG
Sent = Sentinel.Sentinel(trace=DEBUG)
MODELS = Models.Models(API=API)


def not_implemented():
    """ placeholder for missing bits """
    result = {
        "message": "Not implemented"
    }
    return jsonify(result), 500


def _return(data={},  fail_code=400):
    LOGGER.debug("fail_code: %s, data: %s", fail_code, data)
    if 'result' in data and data['result'] is False:
        return data, fail_code
    elif 'result' in data and data['result'] is True:
        return data, 200
    return data, fail_code


#
# expand to take <string:service> as an option and check backend services
#
@API.route('/v1/health', methods=['GET'])
class Health(Resource):
    @API.response(200, 'Success')
    @API.response(500, 'Something is broken')
    def get(self):
        """ Checks this API's health """
        return _return(data={"time": 0, "result": True})


@API.route('/v1/api/version')
class ApiVersion(Resource):
    """ The current running version of the API"""
    def get(self):
        """ Return the API current version """
        return _return(data={"result": True, "time": 0, "version": VERSION})


@API.route('/v1/sentinel/version')
class SentinelVersion(Resource):
    """ The current version of Sentinel """
    def get(self):
        """ Get the current version of Sentinel in the container """
        return _return(data=Sent.sentinel_version())


@API.route('/v1/sys/policies/egp/<path:path>', methods=['post', 'put'])
@API.doc(params={"payload": "${ execution }"})
class QuerySentinelDocument(Resource):
    @API.response(200, 'Success')
    @API.response(400, 'Validation Error')
    @API.expect(MODELS.EXECUTION())
    def post(self, path):
        """ Evaluates the data posted against the policy path queried """
        LOGGER.debug("Validation, received URL: %s", request.path)
        LOGGER.debug("Payload: %s", request.json)
        # sanitize JSON?,
        # should also LOGGER camp?
        SPL = tempfile.NamedTemporaryFile(delete=False,
                                          prefix="_semi_sentinel_")
        SPL.write(json.dumps(request.json).encode('utf-8'))
        # figure out policy from path,
        #  point at policy directory
        if DEBUG:
            path = "/home/vagrant/policy-proxy/examples/sentinel/examples"
            config = "%s/test/pipeline_verification/pass.json" % (path)
            policy = "%s/pipeline_verification.sentinel" % (path)
            res = Sent.sentinel_apply(config=config,
                                      policy=policy)
        else:
            res = Sent.sentinel_apply(config=SPL.name,
                                      policy="%s/%s" % (POLICY_DIR,
                                                        "policy.sentinel"))
        return _return(data=res, fail_code=400)

    @API.response(200, 'Success')
    @API.response(400, 'Validation Error')
    @API.expect(MODELS.POLICY())
    # https://learn.hashicorp.com/vault/identity-access-management/iam-sentinel
    # check for base64 encoding, decode, store as KV..
    def put(self, path):
        """ Inserts a base64 encoded policy at the given EGP on path basis """
        # LOGGER.debug("auth?: %s" % request.headers)
        # Default vault PUT
        if request.mimetype == "application/x-www-form-urlencoded":
            # stream.read first, otherwise data is interpreted
            data = json.loads(request.stream.read())
        elif request.mimetype == "application/json":
            LOGGER.warning("Vault by default does't do json PUTs")
            data = json.loads(request.data)
        else:
            LOGGER.error("Unhandled mimetype: %s" % (request.mimetype))
            return {}
        LOGGER.debug(data)
        LOGGER.debug("putting policies in this way...: %s" % path)


if __name__ == '__main__':
    import logging.config
    logging.basicConfig(stream=sys.stdout,
                        level=logging.DEBUG,
                        format=('%(asctime)s %(name)s %(filename)s:%(lineno)s '
                                '%(funcName)s: %(message)s')
                        )
    LOGGER = logging.getLogger('halyard-api')

    APP.run(debug=True, host="0.0.0.0", port=8001)
