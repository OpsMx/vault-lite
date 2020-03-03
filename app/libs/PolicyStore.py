"""
Simple abstraction layer for policy retrieval and storage, can be moved
to something else later without having to redo anything at the front

Policy path is not the same as filesystem path/location!
"""
import logging
import os
import json
import base64
import glob
LOGGER = logging.getLogger(__name__)
MASK = 0o700


class PolicyStore(object):
    """ Class that handles policies """
    def __init__(self,
                 location="vault-lite/policies",
                 raw_extension="raw",
                 default_extension="sentinel",
                 raw_save=True,
                 trace=False):
        self.location = location
        self.default_extension = default_extension
        self.raw_extension = raw_extension
        self.raw_save = raw_save
        self.trace = trace

    def _checkdir_create(self, location):
        os.makedirs(location, mode=MASK, exist_ok=True)

    def _write_raw_policy(self, key, policy, enforcement_level, paths):
        raw_policy = {
            "policy": policy,
            "paths": paths,
            "enforcement_level": enforcement_level
        }
        try:
            path = "%s.%s" % (self.get_policy_location(key=key),
                              self.raw_extension)
            with open(path, 'w') as outfile:
                json.dump(raw_policy, outfile)
            return True
        except Exception as e:
            LOGGER.error("Unable to save raw policy %s: %s" % (path, e))
        return False

    def _write_simplified_policy(self, key, policy):
        path = self.get_policy_location(key=key)
        try:
            # check if exists deny overrwire, and ask for update??
            f = open(path, 'w+b')
            f.write(policy)
            f.close
            return True
        except Exception as e:
            LOGGER.error("Unable to save policy file %s: %s" % (path, e))
        return False

    """ Remove bas64 encoding for now, get rid of overhead of transforming
        each time, store the raw policy and use the key for the decode bit.
    """
    def store_policy(self,
                     key=None,
                     policy=None,
                     enforcement_level=None,
                     paths=None):
        if key is None or policy is None:
            raise Exception("Missing key or policy")
        self._checkdir_create(self.location)
        if self.raw_save:
            self._write_raw_policy(key, policy, enforcement_level, paths)
        data = base64.b64decode(policy)
        rc = self._write_simplified_policy(key, data)
        return rc

    def get_policy_location(self,
                            key=None):
        return "%s/%s.%s" % (self.location, key, self.default_extension)

    # this should become a read stream at some point...
    def get_policy(self, key=None):
        return open(self.get_policy_location(key=key)).readlines()

    # list all existing policies, raw policies...?
    def list_policies(self):
        pl = []
        policy_files = glob.glob("%s/*.%s" % (self.location,
                                              self.raw_extension))
        LOGGER.debug("Found policies: %s" % policy_files)
        for policy_file in policy_files:
            with open(policy_file) as policy:
                pl.append(json.load(policy))
        return pl

    def delete_policy(self,
                      key=None,
                      paths=None,
                      policy=None):
        return False

    def check_policy(self,
                     key=None,
                     paths=None,
                     policy=None,
                     level=None):
        return {}

    def update_policy(self,
                      key=None,
                      paths=None,
                      policy=None,
                      level=None):
        return {}
