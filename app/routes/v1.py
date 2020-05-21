import json
import tempfile
from flask import request, Response
from flask_restplus import Resource, Namespace
from libs import Sentinel
from libs import Models
from libs import PolicyStore
import logging
import os
import sys
import config
sys.path.append('../')


api = Namespace('v1', description='Vault v1` Relatred actions')
# models = InputModels(api)
Sent = Sentinel.Sentinel(trace=config.TRACE)
MODELS = Models.Models(API=api)
STORE = PolicyStore.PolicyStore(location=config.POLICY_DIR)


def _return(data={},  fail_code=400,  code=200):
    logging.debug("code: %s, fail_code: %s, data: %s",
                  code,
                  fail_code,
                  data)
    status = 400
    if 'result' in data and data['result'] is False:
        status = fail_code
        # Non Vault output gets nice this
        # output = data
        # When vault we should probably parse...
        return json.dumps(data), status
    elif 'result' in data and data['result'] is True:
        status = code
        # Double check this against vault, use it for now to cheat..
        if "data" in data:
            output = json.dumps({"data": data['data'][0]})
        else:
            output = json.dumps({"data": data})
    else:
        output = json.dumps({"msg": data})
    # return output, status
    return Response(output, status=status)


def is_json(data):
    try:
        data = json.loads(data)
        return True
    except json.decoder.JSONDecodeError as e:
        logging.error("Unable to parse JSON, not JSON?: %s" % e)
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
        logging.warning("Vault by default doesn't do json")
    else:
        if is_json(request.data):
            return json.loads(request.data)
        logging.warning("Invalid input; %s" % request.data)
        return {"error": "Input is not JSON"}


# Parse in params later
def prep_sentinel_data(data, params=None):
    ndata = {"mock": data}
    return ndata


@api.route('/health', methods=['GET'])
class Health(Resource):
    @api.response(200, 'Success')
    @api.response(500, 'Something is broken')
    def get(self):
        """ Checks this API's health """
        return _return(data={"time": 0, "result": True})


@api.route('/api/version')
class ApiVersion(Resource):
    """ The current running version of the API"""
    def get(self):
        """ Return the API current version """
        return _return(data={"result": True,
                             "time": 0,
                             "version": config.VERSION})


@api.route('/sentinel/version')
class SentinelVersion(Resource):
    """ The current version of Sentinel """
    def get(self):
        """ Get the current version of Sentinel in the container """
        return _return(data=Sent.sentinel_version())


# Fullfill path?
@api.route('/sys/policies/egp/<path:path>', methods=['put',
                                                     'delete',
                                                     'list',
                                                     'get'])
class PolicyStorage(Resource):
    @api.response(200, 'Success')
    @api.response(400, 'Validation Error')
    @api.expect(MODELS.POLICY())
    # https://learn.hashicorp.com/vault/identity-access-management/iam-sentinel
    # check for base64 encoding, decode, store as KV..
    def put(self, path):
        """ Inserts a base64 encoded policy at the given EGP on path basis """
        # logging.debug("auth?: %s" % request.headers)
        data = get_data_on_mime(request)
        rc = STORE.store_policy(key=path,
                                paths=data['paths'],
                                enforcement_level=data['enforcement_level'],
                                policy=data['policy'])
        logging.debug("rc: %s" % rc)
        data = {
            'data': rc
        }
        return data

    @api.response(200, 'Success')
    @api.response(400, 'Validation Error')
    @api.expect()
    def delete(self, path):
        """ Remove a policy based on its key """
        rc = STORE.delete_policy_on_key(key=path)
        return rc

    """ surplus """
    def list(self):
        """ Lists all known stored policy definitions """
        # logging.debug(request.headers)
        rc = STORE.list_policies()
        return rc

    def get(self, path):
        """ Get a specific policy definition, NOT RAW """
        if path:
            rc = STORE.get_policies_by_key(key=path)
        else:
            rc = STORE.list_policies()
            logging.debug(rc)
        data = {
            "data": {
                path: rc
            }
        }
        return data


# X-Vault-Request:
@api.route('/sys/policies/egp', methods=['list', 'get'])
class PolicySimpleList(Resource):
    @api.response(200, 'Success')
    @api.response(400, 'Validation Error')
    @api.doc(id='get_something')
    # @api.expect()
    def list(self):
        return self.get()

    def get(self):
        data = {}
        """ Lists all known stored policy definitions  """
        rc = STORE.list_policies()
        logging.debug(rc)
        # needs to improve tough....
        for p in rc:
            logging.debug("xx %s" % p)
            data[p['key']] = p
        return {"data": data}, 200


@api.route('/secret/<path:path>', methods=['put',
                                           'post',
                                           'get',
                                           'delete',
                                           'list'])
class Secrets(Resource):
    @api.response(200, 'Success')
    @api.response(400, 'Validation Error')
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


@api.route('/sys/internal/ui/mounts/<path:path>', methods=['get'])
class SysInternalUiMounts(Resource):
    @api.response(200, 'Success')
    @api.response(400, 'Validation Error')
    def get(self, path):
        """ Mock this routine that gets called by vault.
            info:
            https://www.vaultproject.io/api-docs/system/internal-ui-mounts/
        """
        logging.info("Received mount call to: %s" % path)
        return {}

# Fullfill path?
# Here we need to save retrieve the policy based on the path
# and evaluate against the policy based on the paths given with the policy
# - We don't do anything else for now....
@api.route('/<path:path>', methods=['put', 'post'])
class PolicyVerification(Resource):
    @api.response(200, 'Success')
    @api.response(400, 'Validation Error')
    @api.doc(id='get_something')
    # @api.expect()
    def put(self, path):
        """ Evaluates the data PUT against the policy path queried """
        return self.post(path)

    @api.response(200, 'Success')
    @api.response(400, 'Validation Error')
    @api.expect(MODELS.EXECUTION())
    @api.doc(params={"payload": "${ execution }"})
    def post(self, path):
        """ Evaluates the data POSTed against the policy path queried """
        vpath = request.path.split('/', 2)[-1]
        policy_paths = STORE.get_policies_by_path(path=vpath)
        if policy_paths:
            # logging.debug("Valid policy paths: %s" % policy_paths)
            rdata = get_data_on_mime(request)
            if "error" not in rdata:
                data = prep_sentinel_data(rdata)
                file_prefix = config.TEMP_PREFIX
                SPL = tempfile.NamedTemporaryFile(delete=False,
                                                  prefix=file_prefix)
                SPL.write(json.dumps(data).encode('utf-8'))
                SPL.close()
                res = Sent.sentinel_apply(config=SPL.name,
                                          policies=policy_paths)
            else:
                res = rdata
            if not config.DEBUG:
                os.unlink(SPL.name)
            return _return(data=res)
        else:
            msg = "No policies found for path: %s" % vpath
            logging.error(msg)
        return _return(data=msg)
