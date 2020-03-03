"""
Simple abstraction layer for policy retrieval and storage, can be moved
to something else later without having to redo anything at the front
"""
import logging
LOGGER = logging.getLogger(__name__)


class PolicyStore(object):
    """ Class that handles policies """
    def __init__(self,
                 trace=False):
        self.trace = trace

    def check_policy(self,
                     path,
                     policy,
                     level):
        return {}

    def store_policy(self,
                     path=None,
                     policy=None,
                     level=None):
        return {}

    def delete_policy(self,
                      path=None,
                      policy=None):
        return {}

    def update_policy(self,
                      path=None,
                      policy=None,
                      level=None):
        return {}
