#!/bin/python3
"""
Simple Sentinel API to front a standalone simple Sentinel service locally
inside a container, or reach out to Vault Enterprise for policy evaluation

"""
import sys
import os
import json
import tempfile
from flask import Flask, request
from flask_cors import CORS
from flask_restplus import Resource, Api
from libs import Sentinel
from libs import Models
from libs import PolicyStore

VERSION = "0.1"
NAME = "vault-lite-api"
NAME_LABEL = "Vault-lite"
TITLE = "Swaggering ", NAME_LABEL
POLICY_DIR = "vault-lite/policies"
TEMP_DIR = "/tmp"

APP = Flask(__name__)
# restrict CORS later...
CORS(APP, resources="/*")
API = Api(APP,
          doc='/swagger/',
          version=VERSION,
          title=TITLE,
          default=NAME,
          default_label=NAME_LABEL)

DEBUG = True
APP.config["DEBUG"] = DEBUG
Sent = Sentinel.Sentinel(trace=DEBUG)
MODELS = Models.Models(API=API)
STORE = PolicyStore.PolicyStore(location=POLICY_DIR)


def _return(data={},  fail_code=400):
    LOGGER.debug("fail_code: %s, data: %s", fail_code, data)
    if 'result' in data and data['result'] is False:
        return data, fail_code
    elif 'result' in data and data['result'] is True:
        return data, 200
    return data, fail_code


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


# Fullfill path?
@API.route('/v1/sys/policies/egp/<path:path>', methods=['put',
                                                        'delete',
                                                        'list',
                                                        'get'])
class PolicyHandling(Resource):
    @API.response(200, 'Success')
    @API.response(400, 'Validation Error')
    @API.expect(MODELS.POLICY())
    # https://learn.hashicorp.com/vault/identity-access-management/iam-sentinel
    # check for base64 encoding, decode, store as KV..
    def put(self, path):
        """ Inserts a base64 encoded policy at the given EGP on path basis """
        # LOGGER.debug("auth?: %s" % request.headers)
        if request.mimetype == "application/x-www-form-urlencoded":
            # stream.read first, otherwise data is interpreted
            data = json.loads(request.stream.read())
        elif request.mimetype == "application/json":
            LOGGER.warning("Vault by default doesn't do json PUTs")
        else:
            # vault client uses no mimetype...
            LOGGER.error("Unhandled mimetype: %s" % (request.mimetype))
            data = json.loads(request.data)
        rc = STORE.store_policy(key=path,
                                paths=data['paths'],
                                enforcement_level=data['enforcement_level'],
                                policy=data['policy'])
        return {"data": "%s" % rc}

    @API.response(200, 'Success')
    @API.response(400, 'Validation Error')
    @API.expect()
    def delete(self, path):
        """ Remove a policy based on its key """
        rc = STORE.store_delete(key=path)
        return rc

    def list(self):
        """ Lists all known stored policy definitions """
        # LOGGER.debug(request.headers)
        rc = STORE.list_policies()
        return rc

    def get(self, path):
        """ Get a specific policy definition """
        if path:
            rc = STORE.get_policy(path)
        else:
            rc = STORE.list_policies()
        # LOGGER.debug("path: %s, %s" % (path, rc))
        return rc


# X-Vault-Request:
@API.route('/v1/sys/policies/egp', methods=['list', 'get'])
class PolicySimpleList(Resource):
    @API.response(200, 'Success')
    @API.response(400, 'Validation Error')
    @API.doc(id='get_something')
    # @API.expect()
    def list(self):
        """ Lists all known stored policy definitions  """
        rc = STORE.list_policies()
        return rc

    def get(self):
        """ Lists all known stored policy definitions  """
        rc = STORE.list_policies()
        LOGGER.debug(request.headers)
        return rc


# Fullfill path?
# Here we need to save retrieve the policy based on the path
# and evaluate against the policy based on the paths given with the policy
#
@API.route('/v1/<path:path>', methods=['put', 'post'])
class PolicyVerification(Resource):
    @API.response(200, 'Success')
    @API.response(400, 'Validation Error')
    @API.doc(id='get_something')
    # @API.expect()
    def put(self, path):
        """ Evaluates the data PUT against the policy path queried """
        LOGGER.debug(request)

    @API.response(200, 'Success')
    @API.response(400, 'Validation Error')
    @API.expect(MODELS.EXECUTION())
    @API.doc(params={"payload": "${ execution }"})
    def post(self, path):
        """ Evaluates the data POSTed against the policy path queried """
        vpath = request.path.split('/', 2)[-1]
        if request.json is None:
            LOGGER.error("Missing body in request...")
            return 400
        # spool file...
        SPL = tempfile.NamedTemporaryFile(delete=False,
                                          prefix=NAME_LABEL)
        SPL.write(json.dumps(request.json).encode('utf-8'))
        # figure out policy from path,
        #  point at policy directory
        policy_paths = STORE.get_policies_by_path(path=vpath)
        res = Sent.sentinel_apply(config=SPL.name,
                                  policies=policy_paths)
        if not DEBUG:
            os.unlink(SPL.name)
        return _return(data=res, fail_code=400)


if __name__ == '__main__':
    import logging.config
    logging.basicConfig(stream=sys.stdout,
                        level=logging.DEBUG,
                        format=('%(asctime)s %(name)s %(filename)s:%(lineno)s '
                                '%(funcName)s: %(message)s')
                        )
    LOGGER = logging.getLogger(NAME)

    APP.run(debug=True, host="0.0.0.0", port=8001)
