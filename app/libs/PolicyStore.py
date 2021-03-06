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
import time
MASK = 0o700
LOGGER = logging.getLogger(__name__)


class PolicyStore(object):
    """ Class that handles policies """
    def __init__(self,
                 location="vault-lite-store/policies",
                 raw_extension="raw",
                 default_extension="sentinel",
                 raw_save=True,
                 trace=False):
        self.policy_path = "%s/.policy_paths" % (location)
        self.location = location
        self.default_extension = default_extension
        self.raw_extension = raw_extension
        self.raw_save = raw_save
        self.trace = trace
        self.paths = {}
        self._reload_paths()

    def _checkdir_create(self,
                         location):
        os.makedirs(location, mode=MASK, exist_ok=True)

    def _write_raw_policy(self,
                          key,
                          policy,
                          enforcement_level,
                          paths):
        # versioning should become part of the metadata store
        raw_policy = {
            "key": key,
            "policy": policy,
            "paths": paths,
            "enforcement_level": enforcement_level,
            "ctime": time.time(),
            "enabled": True,
            "version": 1
        }
        try:
            path = "%s.%s" % (self._get_policy_location(key=key),
                              self.raw_extension)
            with open(path, 'w') as outfile:
                json.dump(raw_policy, outfile)
            return raw_policy
        except Exception as e:
            LOGGER.error("Unable to save raw policy %s: %s" % (path, e))
        return False

    def _write_simplified_policy(self,
                                 key,
                                 policy):
        path = self._get_policy_location(key=key)
        try:
            # check if exists deny overrwire, and ask for update??
            f = open(path, 'w+b')
            f.write(policy)
            f.close
            return True
        except Exception as e:
            LOGGER.error("Unable to save policy file %s: %s" % (path, e))
        return False

    def _reload_paths(self):
        # if not os.path.exists(self.policy_path):
        return self._create_paths()

    def __pather(self, key, path):
        if path in self.paths and key not in self.paths[path]:
            self.paths[path].append(key)
        else:
            self.paths[path] = [key]

    def _add_paths(self,
                   key,
                   paths):
        if isinstance(paths, list):
            for path in paths:
                self.__pather(key, path)
        else:
            self.__pather(key, paths)
        self._write_paths()
        return self.paths

    def _write_paths(self):
        path = self.policy_path
        try:
            with open(path, 'w') as outfile:
                json.dump(self.paths, outfile)
            return True
        except Exception as e:
            LOGGER.error("Unable to save policy path file %s: %s" % (path, e))
        return False

    def _create_paths(self):
        policies = self.list_policies()
        for policy in policies:
            if "key" in policy and "paths" in policy:
                self._add_paths(policy['key'], policy['paths'])
        self._write_paths()
        return self.paths

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
        results = {}
        self._checkdir_create(self.location)
        if self.raw_save:
            results = self._write_raw_policy(key,
                                             policy,
                                             enforcement_level,
                                             paths)
        data = base64.b64decode(policy)
        results['simplified_save'] = self._write_simplified_policy(key, data)
        # self._add_paths(key, paths)
        results['time'] = time.time()
        results['key'] = key
        results['version'] = 1
        results['enabled'] = True
        self._reload_paths()
        return results

    def _get_policy_location(self,
                             key=None):
        return "%s/%s.%s" % (self.location, key, self.default_extension)

    # this should become a read stream at some point...
    def get_policies_by_key(self,
                            key=None,
                            path=None):
        if key is None:
            return self.get_policies_by_path(path=path)
        if path is None:
            p = "".join(open(self._get_policy_location(key=key)).readlines())
            return p
        return ""

    def _get_raw_policy_by_key(self,
                               key=None):
        pfile = "%s.%s" % (self._get_policy_location(key=key),
                           self.raw_extension)
        p = "".join(open(pfile).readlines())
        return p

    # should move from more to less specific
    def get_policies_by_path(self,
                             path=None):
        policies = []
        if path in self.paths:
            for key in self.paths[path]:
                policies.append(self._get_policy_location(key=key))
        return policies

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

    # deletion should be a metadata party, not a data party...
    # if we'd expand on thise
    def delete_policy_on_key(self,
                             key=None):
        rm = []
        for path in self.paths:
            if key in self.paths[path]:
                self.paths[path].remove(key)
                pfile = self._get_policy_location(key)
                rawfile = "%s.%s" % (pfile, self.raw_extension)
                if os.path.exists(pfile):
                    os.rename(pfile, "%s.%s" % (pfile, "disable"))
                if os.path.exists(rawfile):
                    os.rename(rawfile, "%s.%s" % (rawfile, "disable"))
            if not self.paths[path]:
                rm.append(path)
        for path in rm:
            self.paths.pop(path)
        return self._create_paths()

    def delete_policies_on_path(self,
                                path=None):
        if path in self.paths:
            for key in self.paths[path]:
                self.delete_policy_on_key(key=key)
        return self._create_paths()

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
