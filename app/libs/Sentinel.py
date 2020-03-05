"""
A simple Sentinel Wrapper that does the prepwork to create a policy test
hierarchy. It allows for writing policy to disk, and calling policy evaluation
wrapped around the sentinel binary.

NOTES:

"""
# import shlex
import re
# import json
import time
from subprocess import check_output, CalledProcessError
import logging
LOGGER = logging.getLogger(__name__)


class Sentinel(object):
    """ Class that talks to Sentinel in some way and preps its input """
    def __init__(self,
                 trace=False):
        self.trace = trace

    # make output look somewhat look like usable
    def sanitize_output(self,
                        input=input):
        state = "Fail"
        _trace = False
        trace = []
        comment = []

        if input.pop(0) == "Pass":
            state = "Pass"
        while input:
            line = input.pop(0)
            if re.match('(\s+)?(TRUE|FALSE)', line):
                _trace = True
                # LOGGER.debug("A-Z: %s" % line)
            if _trace:
                if re.match('\t', line):
                    trace[-1] = "%s %s" % (trace[-1], line.replace('\t', ''))
                else:
                    trace.append(line)
            else:
                if line != "":
                    comment.append(line)

        return {"state": state, "trace:": trace, "comment": comment}

    # We only use this for now...
    # -config <file> policy.sentinel
    # -param
    # -trace
    def sentinel_apply(self,
                       config=False,
                       param=False,
                       policy=False,
                       policies=False):
        rc = []
        if policies:
            for policy in policies:
                rc.append(self._sentinel_apply(config=config,
                                               param=param,
                                               policy=policy))
        elif policy:
            rc.append(self._sentinel_apply(config=config,
                                           param=param,
                                           policy=policy))
        #
        # Should evaluate the policy enforcement_level
        #   hard-mandatory: Fail break it
        #   soft-mandatory: ?
        #   other:          Doesn't matter
        result = True
        r = any(p['result'] is False for p in rc)
        if r:
            result = False
        return {"result": result, "data": rc}

    def _sentinel_apply(self,
                        config=False,
                        param=False,
                        policy=False):
        start = time.time()
        try:
            if not config or not policy:
                raise ValueError("Expecting a config and a policy, got none")
            cmd = ["sentinel", "apply", "-config", config, policy]
            if self.trace:
                cmd.insert(2, "-trace")
            LOGGER.debug("Sentinel CMD: %s" % cmd)
            result = check_output(cmd).decode('utf-8').split("\n")
            output = self.sanitize_output(input=result)
            if output["state"] != "Pass":
                rc = False
            else:
                rc = True
            output['time'] = time.time() - start
            output['result'] = rc
            return output
        except CalledProcessError as e:
            LOGGER.warning("Evaluation failed: %s" % e)
            result = e.output.decode('utf-8').split("\n")
            output = self.sanitize_output(input=result)
            output['time'] = time.time() - start
            output['result'] = False
            return output
        except Exception as e:
            LOGGER.error("Exception caught: %s" % e)
            return {"result": False,
                    "time": time.time() - start,
                    "data": "I can't do that Dave: %s" % e}

    # -write=true, write to file, not stdout
    # -check=false, check formatting
    def sentinel_fmt(self):
        self._sentinel_exec("fmt")

    # Just checks based on local file
    def sentinel_test(self):
        self._sentinel_exec("test")

    # return version
    def sentinel_version(self):
        start = time.time()
        try:
            result = check_output(["sentinel",
                                   "version"])
            name, ver = result.decode("utf-8").rstrip().split(" ")
            LOGGER.debug("name: %s, ver: %s" % (name, ver))
            return {"result": True,
                    "time": time.time() - start,
                    "version": ver}
        except Exception as e:
            LOGGER.error("Exception caught: %s" % e)
            return {"result": False,
                    "time": time.time() - start,
                    "msg": "I can't do that Dave: %s" % e}
