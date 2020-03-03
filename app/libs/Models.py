""" Holds the models used for Swagger """
from flask_restplus import Resource, fields
import logging
LOGGER = logging.getLogger(__name__)


class Models(Resource):
    def __init__(self,
                 API=None):
        self.API = API

    def EXECUTION(self):
        EXECUTION = self.API.model('PipeLineExecutionContext', {
            'pipelineConfigId': fields.String(description=""" The id of the
                                                          spinnaker pipeline
                                                          id """,
                                              default=""" f779bb0e-2519-44dc-
                                                      8ab3-ff357822ab23 """,
                                              required=True),
            'origin': fields.String(desciprion=""" Origin of triggering the
                                               pipeline """,
                                    default="api",
                                    required=True),
            'id': fields.String(desciprion=""" Reference id in spinnaker for
                                           this pipeline """,
                                default="01E21CMPWYM0NQ33XZ2JGG9FN2",
                                required=True),
            'status': fields.String(desciprion=""" Origin of triggering the
                                               pipeline """,
                                    default="RUNNING",
                                    required=True)
        })
        return EXECUTION

    def POLICY(self):
        POLICY = self.API.model('VaultPolicy', {
            'policy': fields.String(description=""" base64 encoded policy """,
                                    required=True),
            'paths': fields.List(fields.String,
                                 desciprion=""" IGNORED, Vault paths this
                                            policy applies to """,
                                 default="secrets/spinnaker/*",
                                 required=True),
            'enforcement_level': fields.String(desciprion=""" IGNORED, Vault
                                                          enforcement level
                                                          either
                                                          hard-mandatory,
                                                          soft-mandatory
                                                          or advisory.  """,
                                               default="hard-mandatory",
                                               required=True),
        })
        return POLICY
