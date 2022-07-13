# Copyright (C) 2020 Extreme Networks, Inc - All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import


import json
import requests
import saml2
import saml2.client
import saml2.config
import six

from st2auth.sso import base as st2auth_sso
from st2common import log as logging
from st2common.exceptions import auth as auth_exc


__all__ = [
    'SAML2SingleSignOnBackend'
]

LOG = logging.getLogger(__name__)


class SAML2SingleSignOnBackend(st2auth_sso.BaseSingleSignOnBackend):
    """
    SAML2 SSO authentication backend.
    """

    MANDATORY_SAML_RESPONSE_ATTRIBUTES = ['Username']

    def _is_valid_role_mapping(self, role_mapping):
        # Supposed to be a dict!
        if not isinstance(role_mapping, dict):
            return False
        # Each entry has to be a list[str]
        for k,v in role_mapping.items():
            # k = str
            # v = list
            if not isinstance(k, str) \
                or not isinstance(v, list):
                return False
            # v is ssupposed to be a list[str]
            for r in v:
                if not isinstance(r, str):
                    return False
        return True

    def __init__(self, entity_id, metadata_url, role_mapping=None, debug=False):
        self.entity_id = entity_id
        self.https_acs_url = '%s/auth/sso/callback' % self.entity_id
        self.saml_metadata_url = metadata_url
        self.saml_metadata = requests.get(self.saml_metadata_url)

        if role_mapping:
            LOG.debug("Validating role mapping configuration")
            if not self._is_valid_role_mapping(role_mapping):
                raise TypeError("invalid 'role_mapping' parameter - "
                    "it is supposed to be a dict[str, list[str]] object!")

            self.role_mapping = role_mapping
            LOG.info("Role mapping configuration: %s", role_mapping)

        LOG.debug('METADATA GET FROM "%s": %s' % (self.saml_metadata_url, self.saml_metadata.text))

        self.saml_client_settings = {
            'entityid': self.entity_id,
            'metadata': {
                'inline': [self.saml_metadata.text]
            },
            'service': {
                'sp': {
                    'endpoints': {
                        'assertion_consumer_service': [
                            (self.https_acs_url, saml2.BINDING_HTTP_REDIRECT),
                            (self.https_acs_url, saml2.BINDING_HTTP_POST)
                        ],
                    },
                    # Don't verify that the incoming requests originate from us via
                    # the built-in cache for authn request ids in pysaml2
                    'allow_unsolicited': True,
                    # Don't sign authn requests, since signed requests only make
                    # sense in a situation where you control both the SP and IdP
                    'authn_requests_signed': False,
                    'logout_requests_signed': True,
                    'want_assertions_signed': True,
                    'want_response_signed': True
                }
            }
        }

        if debug:
            self.saml_client_settings['debug'] = 1

    def _get_single_saml_attribute_or_none(self, authn_response, field):
        if field in authn_response.ava and len(authn_response.ava[field]) > 0:
            return str(authn_response.ava[field][0])
        return None

    def _get_saml_attribute_list_or_empty(self, authn_response, field):
        return authn_response.ava[field] if field in authn_response.ava else []

    def _get_saml_client(self):
        saml_config = saml2.config.Config()
        saml_config.load(self.saml_client_settings)
        saml_config.allow_unknown_attributes = True

        return saml2.client.Saml2Client(config=saml_config)

    def _handle_verification_error(self, error_message, *args):
        raise ValueError(error_message % args)

    def get_request_redirect_url(self, id, referer):
        if not referer.startswith(self.entity_id) and not referer.startswith("http://localhost:"):
            self._handle_verification_error('Invalid referer -- '\
                'it should be either some localhost endpoint or the SSO configured entity')

        relay_state = {
            'referer': referer
        }

        saml_client = self._get_saml_client()
        reqid, info = saml_client.prepare_for_authenticate(
            relay_state=json.dumps(relay_state),
            message_id=id
        )

        # Get the IdP URL to send the SAML request to.
        redirect_url = [v for k, v in six.iteritems(dict(info['headers'])) if k == 'Location'][0]

        return redirect_url

    def _get_authn_response_from_response(self, response):
        if not hasattr(response, 'SAMLResponse'):
            self._handle_verification_error('The SAMLResponse attribute is missing.')

        if getattr(response, 'SAMLResponse', None) is None:
            self._handle_verification_error('The SAMLResponse attribute is null.')

        # The SAMLResponse is an array and it cannot be empty.
        if not isinstance(getattr(response, 'SAMLResponse'), list) \
            or len(getattr(response, 'SAMLResponse')) == 0 \
            or not isinstance(getattr(response, 'SAMLResponse')[0], str):
            self._handle_verification_error('The SAMLResponse attribute should be a list of one or more strings')

        # Parse the response and verify signature.
        saml_response = getattr(response, 'SAMLResponse')[0]

        saml_client = self._get_saml_client()

        try:
            LOG.debug("Parsing authn response")
            return saml_client.parse_authn_request_response(
                saml_response,
                saml2.BINDING_HTTP_POST
            )
        except saml2.validate.ResponseLifetimeExceed as e:
            LOG.debug("SAML response is too old, error: %s", e)
            self._handle_verification_error("SAML response is too old!")

    def _map_roles(self, sso_roles):
        granted_roles = []
        for sso_role in sso_roles:
            granted_roles += self.role_mapping.get(sso_role, [])
        return list(set(granted_roles))

    def get_request_id_from_response(self, response):
        authn_response = self._get_authn_response_from_response(response)
        return getattr(authn_response, 'in_response_to', None)

    def verify_response(self, response):
        try:

            # The relay state is set by the Sp -> Idp -> Sp flow. If the flow is started by the Idp,
            # the relay state is not set. Verify that the unique value passed as relay state during
            # the request step is the same given back here. The referer address should also be
            # restricted to starts with the address of the Sp (or entity id).
            has_relay_state = hasattr(response, 'RelayState')

            if has_relay_state and getattr(response, 'RelayState', None) is None:
                self._handle_verification_error('The RelayState attribute is null.')

            # The RelayState is an array and it cannot be empty.
            if has_relay_state and len(getattr(response, 'RelayState')) <= 0:
                self._handle_verification_error('The RelayState attribute is empty.')

            relay_state = json.loads(getattr(response, 'RelayState')[0]) if has_relay_state else {}
            LOG.debug("Incoming relay state is [%s]", relay_state)

            if has_relay_state:
                if 'referer' not in relay_state:
                    self._handle_verification_error('The RelayState is missing the referer')
                elif not relay_state['referer'].startswith(self.entity_id):
                    self._handle_verification_error('The RelayState referer [%s] is not allowed.'
                        ' It must come from the trusted SAML entity', relay_state['referer'])

            authn_response = self._get_authn_response_from_response(response)

            if not authn_response:
                self._handle_verification_error('Unable to parse the data in SAMLResponse.')

            LOG.debug("Validating expected fields are present: %s",
                self.MANDATORY_SAML_RESPONSE_ATTRIBUTES)

            for field in self.MANDATORY_SAML_RESPONSE_ATTRIBUTES:
                if self._get_single_saml_attribute_or_none(authn_response, field) is None:
                    self._handle_verification_error('Expected field "%s" to be present \
                        in the SAML response!', field)

            sso_roles = self._get_saml_attribute_list_or_empty(authn_response, 'Role')
            roles = self._map_roles(sso_roles)

            LOG.debug("Roles received from SSO [%s] are mapped to: %s", sso_roles, roles)

            #
            # At this point, SAML response is valid, and wee good :)
            #

            verified_user = {
                'referer': relay_state.get('referer') or self.entity_id,
                'username': self._get_single_saml_attribute_or_none(authn_response, 'Username'),
                'roles': roles
            }
        except ValueError:
            raise
        except Exception:
            message = 'Error encountered while verifying the SAML2 response.'
            LOG.exception(message)
            raise auth_exc.SSOVerificationError(message)

        return verified_user
