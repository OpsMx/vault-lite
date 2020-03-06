#!/bin/python3
"""
Simple Sentinel API to front a standalone simple Sentinel service locally
inside a container, or reach out to Vault Enterprise for policy evaluation

"""
import sys
import os
import json
import tempfile
import logging
from flask import Flask, request, Response
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
TRACE = True
APP.config["DEBUG"] = DEBUG
Sent = Sentinel.Sentinel(trace=TRACE)
MODELS = Models.Models(API=API)
STORE = PolicyStore.PolicyStore(location=POLICY_DIR)


def _return(data={},  fail_code=400,  code=200):
    LOGGER.debug("code: %s, fail_code: %s, data: %s", code, fail_code, data)
    status = 400
    if 'result' in data and data['result'] is False:
        status = fail_code
        # Non Vault output gets nice this
        # output = data
        # When vault we should probably parse...
        output = json.dumps(data, sort_keys=True, indent=4)
        return output, status
    elif 'result' in data and data['result'] is True:
        status = code
        output = json.dumps({"data": data['data'][0]})
    else:
        output = json.dumps({"msg": data})
    # return output, status
    return Response(output, status=status)


def is_json(data):
    try:
        data = json.loads(data)
        return True
    except json.decoder.JSONDecodeError as e:
        LOGGER.error("Unable to parse JSON, not JSON?: %s" % e)
    return False


# clean error returning..
def get_data_on_mime(request):
    if request.mimetype == "application/x-www-form-urlencoded":
        # stream.read first, otherwise data is interpreted
        read = request.stream.read()
        if is_json(read):
            return json.loads(read)
        return {"error": "Input is not JSON"}
    elif request.mimetype == "application/json":
        LOGGER.warning("Vault by default doesn't do json")
    else:
        if is_json(request.data):
            return json.loads(request.data)
        LOGGER.warning("Invalid input; %s" % request.data)
        return {"error": "Input is not JSON"}


# Parse in params later
def prep_sentinel_data(data, params=None):
    ndata = {"mock": data}
    return ndata


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
class PolicyStorage(Resource):
    @API.response(200, 'Success')
    @API.response(400, 'Validation Error')
    @API.expect(MODELS.POLICY())
    # https://learn.hashicorp.com/vault/identity-access-management/iam-sentinel
    # check for base64 encoding, decode, store as KV..
    def put(self, path):
        """ Inserts a base64 encoded policy at the given EGP on path basis """
        # LOGGER.debug("auth?: %s" % request.headers)
        data = get_data_on_mime(request)
        rc = STORE.store_policy(key=path,
                                paths=data['paths'],
                                enforcement_level=data['enforcement_level'],
                                policy=data['policy'])
        LOGGER.debug("rc: %s" % rc)
        data = {
            'data': rc
        }
        return data

    @API.response(200, 'Success')
    @API.response(400, 'Validation Error')
    @API.expect()
    def delete(self, path):
        """ Remove a policy based on its key """
        rc = STORE.delete_policy_on_key(key=path)
        return rc

    """ surplus """
    def list(self):
        """ Lists all known stored policy definitions """
        # LOGGER.debug(request.headers)
        rc = STORE.list_policies()
        return rc

    def get(self, path):
        """ Get a specific policy definition, NOT RAW """
        if path:
            rc = STORE.get_policies_by_key(key=path)
        else:
            rc = STORE.list_policies()
            LOGGER.debug(rc)
        data = {
            "data": {
                path: rc
            }
        }
        return data


# X-Vault-Request:
@API.route('/v1/sys/policies/egp', methods=['list', 'get'])
class PolicySimpleList(Resource):
    @API.response(200, 'Success')
    @API.response(400, 'Validation Error')
    @API.doc(id='get_something')
    # @API.expect()
    def list(self):
        return self.get()

    def get(self):
        data = {}
        """ Lists all known stored policy definitions  """
        rc = STORE.list_policies()
        LOGGER.debug(rc)
        # needs to improve tough....
        for p in rc:
            LOGGER.debug("xx %s" % p)
            data[p['key']] = p
        return {"data": data}, 200


@API.route('/v1/secret/<path:path>', methods=['put',
                                              'post',
                                              'get',
                                              'delete',
                                              'list'])
class Secrets(Resource):
    @API.response(200, 'Success')
    @API.response(400, 'Validation Error')
    def put(self):
        """ Not implemented """
        pass

    def post(self):
        """ Not implemented """
        pass

    def get(self):
        """ Not implemented """
        pass

    def delete(self):
        """ Not implemented """
        pass

    def list(self):
        """ Not implemented """
        pass


@API.route('/v1/sys/internal/ui/mounts/<path:path>', methods=['get'])
class SysInternalUiMounts(Resource):
    @API.response(200, 'Success')
    @API.response(400, 'Validation Error')
    def get(self, path):
        """ Mock this routine that gets called by vault.
            info:
            https://www.vaultproject.io/api-docs/system/internal-ui-mounts/
        """
        LOGGER.info("Received mount call to: %s" % path)
        return {}

# Fullfill path?
# Here we need to save retrieve the policy based on the path
# and evaluate against the policy based on the paths given with the policy
# - We don't do anything else for now....
@API.route('/v1/<path:path>', methods=['put', 'post'])
class PolicyVerification(Resource):
    @API.response(200, 'Success')
    @API.response(400, 'Validation Error')
    @API.doc(id='get_something')
    # @API.expect()
    def put(self, path):
        """ Evaluates the data PUT against the policy path queried """
        return self.post(path)

    @API.response(200, 'Success')
    @API.response(400, 'Validation Error')
    @API.expect(MODELS.EXECUTION())
    @API.doc(params={"payload": "${ execution }"})
    def post(self, path):
        """ Evaluates the data POSTed against the policy path queried """
        vpath = request.path.split('/', 2)[-1]
        policy_paths = STORE.get_policies_by_path(path=vpath)
        if policy_paths:
            rdata = get_data_on_mime(request)
            if "error" not in rdata:
                data = prep_sentinel_data(rdata)
                SPL = tempfile.NamedTemporaryFile(delete=False,
                                                  prefix=NAME_LABEL)
                SPL.write(json.dumps(data).encode('utf-8'))
                res = Sent.sentinel_apply(config=SPL.name,
                                          policies=policy_paths)
            else:
                res = rdata
            if not DEBUG:
                os.unlink(SPL.name)
            return _return(data=res)
        else:
            msg = "No policies found for path: %s" % vpath
            LOGGER.error(msg)
        return _return()


if __name__ == '__main__':
    import logging.config
    logging.basicConfig(stream=sys.stdout,
                        level=logging.DEBUG,
                        format=('%(asctime)s %(name)s %(filename)s:%(lineno)s '
                                '%(funcName)s: %(message)s')
                        )
    LOGGER = logging.getLogger(NAME)

    APP.run(debug=True, host="0.0.0.0", port=8200)