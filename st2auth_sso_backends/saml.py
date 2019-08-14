# Copyright (C) 2019 Extreme Networks, Inc - All Rights Reserved
#
# Unauthorized copying of this file, via any medium is strictly
# prohibited. Proprietary and confidential. See the LICENSE file
# included with this work for details.

from __future__ import absolute_import

import json
import requests
import saml2
import saml2.client
import saml2.config
import six
import uuid

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

    def __init__(self, *args, **kwargs):
        self.entity_id = kwargs['entity_id']
        self.relay_state_id = uuid.uuid4().hex
        self.https_acs_url = '%s/auth/sso/callback' % self.entity_id
        self.saml_metadata_url = kwargs['metadata_url']
        self.saml_metadata = requests.get(self.saml_metadata_url)

        LOG.info(self.saml_metadata.text)

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

    def _get_relay_state_id(self):
        return self.relay_state_id

    def _get_saml_client(self):
        saml_config = saml2.config.Config()
        saml_config.load(self.saml_client_settings)
        saml_config.allow_unknown_attributes = True

        return saml2.client.Saml2Client(config=saml_config)

    def _handle_verification_error(self, error_message):
        raise auth_exc.SSOVerificationError(error_message)

    def get_request_redirect_url(self, referer):
        if not referer.startswith(self.entity_id):
            self._handle_verification_error('Invalid referer.')

        # The relay state will be echo back from the Idp. This adds another layer of
        # verification to ensure the unique value passed during the request step is
        # the same value passed back during the response step. We will also use
        # the referer value to redirect user back to the original page.
        relay_state = {
            'id': self.relay_state_id,
            'referer': referer
        }

        saml_client = self._get_saml_client()
        reqid, info = saml_client.prepare_for_authenticate(relay_state=json.dumps(relay_state))

        # Get the IdP URL to send the SAML request to.
        redirect_url = [v for k, v in six.iteritems(dict(info['headers'])) if k == 'Location'][0]

        return redirect_url

    def verify_response(self, response):
        try:
            if not hasattr(response, 'SAMLResponse'):
                self._handle_verification_error('The SAMLResponse attribute is missing.')

            if getattr(response, 'SAMLResponse', None) is None:
                self._handle_verification_error('The SAMLResponse attribute is null.')

            if len(getattr(response, 'SAMLResponse')) <= 0:
                self._handle_verification_error('The SAMLResponse attribute is empty.')

            # The relay state is set by the Sp -> Idp -> Sp flow. If the flow is started by the Idp,
            # the relay state is not set. Verify that the unique value passed as relay state during
            # the request step is the same given back here. The referer address should also be
            # restricted to starts with the address of the Sp (or entity id).
            has_relay_state = hasattr(response, 'RelayState')

            if has_relay_state and getattr(response, 'RelayState', None) is None:
                self._handle_verification_error('The RelayState attribute is null.')

            if has_relay_state and len(getattr(response, 'RelayState')) <= 0:
                self._handle_verification_error('The RelayState attribute is empty.')

            relay_state = json.loads(getattr(response, 'RelayState')[0]) if has_relay_state else {}

            if (has_relay_state and (
                    'id' not in relay_state or 'referer' not in relay_state or
                    self._get_relay_state_id() != relay_state['id'] or
                    not relay_state['referer'].startswith(self.entity_id))):
                error_message = 'The value of the RelayState in the response does not match.'
                self._handle_verification_error(error_message)

            # Parse the response and verify signature.
            saml_response = getattr(response, 'SAMLResponse')[0]
            saml_client = self._get_saml_client()

            authn_response = saml_client.parse_authn_request_response(
                saml_response,
                saml2.BINDING_HTTP_POST
            )

            if not authn_response:
                self._handle_verification_error('Unable to parse the data in SAMLResponse.')

            verified_user = {
                'referer': relay_state.get('referer') or self.entity_id,
                'username': str(authn_response.ava['Username'][0]),
                'email': str(authn_response.ava['Email'][0]),
                'last_name': str(authn_response.ava['LastName'][0]),
                'first_name': str(authn_response.ava['FirstName'][0])
            }
        except Exception:
            message = 'Error encountered while verifying the SAML2 response.'
            LOG.exception(message)
            raise auth_exc.SSOVerificationError(message)

        return verified_user
