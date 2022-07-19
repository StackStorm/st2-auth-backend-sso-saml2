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
import mock
import saml2
import urllib
import re

import os

import requests

from oslo_config import cfg
from six.moves import http_client

import st2auth
from st2auth import sso as st2auth_sso
from st2auth import app
from st2auth.sso.base import BaseSingleSignOnBackendResponse
from st2auth_sso_saml2 import saml
from st2common.router import GenericRequestParam
from st2tests import config
from st2tests import DbTestCase
from st2tests.api import TestApp
from st2common.services.access import create_web_sso_request


# Lods a fixture file from within the fixtures/ directory :)
def load_fixture(path):
    return open(os.path.join(os.path.dirname(__file__), "fixtures", path)).read()


SSO_V1_PATH = "/v1/sso"
SSO_REQUEST_V1_PATH = SSO_V1_PATH + "/request/web"
SSO_CALLBACK_V1_PATH = SSO_V1_PATH + "/callback"

MOCK_ENTITY_ID = "http://localhost"
MOCK_ACS_URL = "%s/auth/sso/callback" % MOCK_ENTITY_ID
# We need this format for the certs to work
MOCK_IDP_URL = "http://keycloak:8080/realms/stackstorm"
MOCK_IDP_SAML_URL = "%s/protocol/saml" % MOCK_IDP_URL
MOCK_METADATA_URL = "%s/protocol/saml/descriptor" % MOCK_IDP_URL

MOCK_SAML_RESPONSE_REQUEST_ID = "id_38c65e6f-124c-451f-8ff8-407e1799818e"
MOCK_SAML_RESPONSE = load_fixture("saml_response_valid_with_roles.txt")

MOCK_SAML_METADATA_TEXT = load_fixture("saml_metadata.xml")

MOCK_USER_USERNAME = "stanley"
MOCK_USER_EMAIL = "stanley@stackstorm.com"
MOCK_USER_LASTNAME = "Stormin"
MOCK_USER_FIRSTNAME = "Stanley"


class MockSamlMetadata(object):
    def __init__(self, text="foobar"):
        self.text = MOCK_SAML_METADATA_TEXT


class MockAuthnResponse(object):
    def __init__(self):
        self.ava = {
            "Username": MOCK_USER_USERNAME,
            "Email": MOCK_USER_EMAIL,
            "LastName": MOCK_USER_LASTNAME,
            "FirstName": MOCK_USER_FIRSTNAME,
        }


class BaseSAML2Controller(DbTestCase):

    automatically_setup_backend = True
    default_sso_backend_kwargs = {
        "metadata_url": MOCK_METADATA_URL,
        "entity_id": MOCK_ENTITY_ID,
    }
    backend_instance = None

    old_get_saml_client = None

    # Wraps the appropriate method to ignore old saml responses
    def _ignore_old_saml_response_setup(self):
        old = self.old_get_saml_client = saml.SAML2SingleSignOnBackend._get_saml_client

        def wrapper(self):
            client = old(self)
            client.config.accepted_time_diff = 10000000
            return client

        saml.SAML2SingleSignOnBackend._get_saml_client = wrapper

    # Restore the default get_saml_client method to not ignore old saml reponses any longer :o
    def _ignore_old_saml_response_teardown(self):
        saml.SAML2SingleSignOnBackend._get_saml_client = self.old_get_saml_client

    @classmethod
    @mock.patch.object(requests, "get", mock.MagicMock(return_value=MockSamlMetadata()))
    def setupBackendConfig(
        cls, sso_backend_kwargs=default_sso_backend_kwargs, **kwargs
    ):
        config.parse_args()
        kwargs_json = json.dumps(sso_backend_kwargs)
        cfg.CONF.set_override(name="sso", override=True, group="auth")
        cfg.CONF.set_override(name="sso_backend", override="saml2", group="auth")
        cfg.CONF.set_override(
            name="sso_backend_kwargs", override=kwargs_json, group="auth"
        )

        cls.app = TestApp(app.setup_app(), **kwargs)

        # Delay import here otherwise setupClass will not have run.
        from st2auth.controllers.v1 import sso as sso_api_controller

        cls.backend_instance = (
            sso_api_controller.SSO_BACKEND
        ) = st2auth_sso.get_sso_backend()

        return cls.backend_instance

    @classmethod
    def setUpClass(cls, **kwargs):
        super(BaseSAML2Controller, cls).setUpClass()

        if cls.automatically_setup_backend:
            BaseSAML2Controller.setupBackendConfig(
                cls.default_sso_backend_kwargs, **kwargs
            )


# Tests for initialization
class TestSAMLSSOBackendInitialization(BaseSAML2Controller):

    automatically_setup_backend = False

    def _test_cls_init_default_assertions(self, backend_config):
        instance = self.setupBackendConfig(backend_config)
        self.assertEqual(instance.entity_id, MOCK_ENTITY_ID)
        self.assertEqual(instance.https_acs_url, MOCK_ACS_URL)
        self.assertEqual(instance.saml_metadata_url, MOCK_METADATA_URL)

        expected_saml_client_settings = {
            "entityid": MOCK_ENTITY_ID,
            "metadata": {"inline": [MockSamlMetadata().text]},
            "service": {
                "sp": {
                    "endpoints": {
                        "assertion_consumer_service": [
                            (MOCK_ACS_URL, saml2.BINDING_HTTP_REDIRECT),
                            (MOCK_ACS_URL, saml2.BINDING_HTTP_POST),
                        ]
                    },
                    "allow_unsolicited": True,
                    "authn_requests_signed": False,
                    "logout_requests_signed": True,
                    "want_assertions_signed": True,
                    "want_response_signed": True,
                }
            },
        }

        self.assertDictEqual(
            instance.saml_client_settings, expected_saml_client_settings
        )

    def test_cls_init_no_roles(self):
        self._test_cls_init_default_assertions(
            {"metadata_url": MOCK_METADATA_URL, "entity_id": MOCK_ENTITY_ID}
        )

    def test_cls_init_valid_roles(self):
        self._test_cls_init_default_assertions(
            {
                "metadata_url": MOCK_METADATA_URL,
                "entity_id": MOCK_ENTITY_ID,
                "role_mapping": {"test_role": ["test", "123"]},
            }
        )

    def test_cls_init_invalid_roles_spec_list_of_number(self):
        self.assertRaisesRegex(
            TypeError,
            (
                "invalid 'role_mapping' parameter - it is supposed to be"
                r" a dict\[str, list\[str\]\] object or None!"
            ),
            self.setupBackendConfig,
            {
                "metadata_url": MOCK_METADATA_URL,
                "entity_id": MOCK_ENTITY_ID,
                "role_mapping": {
                    "test_role1": ["123", "role2"],
                    "test_role": [123, 333],
                },
            },
        )

    def test_cls_init_invalid_roles_spec_string(self):
        self.assertRaisesRegex(
            TypeError,
            (
                "invalid 'role_mapping' parameter - it is supposed to be"
                r" a dict\[str, list\[str\]\] object or None!"
            ),
            self.setupBackendConfig,
            {
                "metadata_url": MOCK_METADATA_URL,
                "entity_id": MOCK_ENTITY_ID,
                "role_mapping": {"test_role": "test"},
            },
        )

    def test_cls_init_missing_args(self):
        self.assertRaisesRegex(
            TypeError,
            "missing 1 required positional argument: 'entity_id'",
            self.setupBackendConfig,
            {"metadata_url": MOCK_METADATA_URL},
        )

    def test_cls_init_invalid_args(self):
        self.assertRaisesRegex(
            TypeError,
            "got an unexpected keyword argument 'invalid'",
            self.setupBackendConfig,
            {
                "metadata_url": MOCK_METADATA_URL,
                "entity_id": MOCK_ENTITY_ID,
                "invalid": 123,
            },
        )


# Tests for SAML backend functionality
class TestSAMLSSOBackend(BaseSAML2Controller):

    automatically_setup_backend = False

    # Standard logic for these verify_response tests
    def _test_verify_response_helper(
        self,
        backend_config=BaseSAML2Controller.default_sso_backend_kwargs,
        saml_response=MOCK_SAML_RESPONSE,
        relay_state=[json.dumps({"referer": MOCK_ENTITY_ID})],
        role_mapping=None,
        expected_result=None,
    ):
        self._ignore_old_saml_response_setup()

        if role_mapping:
            backend_config = {**backend_config, **{"role_mapping": role_mapping}}

        self.setupBackendConfig(backend_config)

        response = self.backend_instance.verify_response(
            GenericRequestParam(SAMLResponse=[saml_response], RelayState=relay_state)
        )
        self.assertEqual(response, expected_result)

        self._ignore_old_saml_response_teardown()
        return response

    def test_verify_response(self):
        self._test_verify_response_helper(
            expected_result=BaseSingleSignOnBackendResponse(
                username="guilherme.pim", referer=MOCK_ENTITY_ID, roles=[]
            )
        )

    def test_verify_response_with_roles_empty(self):
        self._test_verify_response_helper(
            role_mapping={"test": ["observer", "admin"]},
            expected_result=BaseSingleSignOnBackendResponse(
                username="guilherme.pim", referer=MOCK_ENTITY_ID, roles=[]
            ),
        )

    def test_verify_response_with_roles_one_match(self):
        self._test_verify_response_helper(
            role_mapping={"default-roles-stackstorm": ["observer", "admin"]},
            expected_result=BaseSingleSignOnBackendResponse(
                username="guilherme.pim",
                referer=MOCK_ENTITY_ID,
                roles=["admin", "observer"],
            ),
        )

    def test_verify_response_with_roles_multiple_match(self):
        self._test_verify_response_helper(
            role_mapping={
                "default-roles-stackstorm": ["observer", "admin"],
                "view-profile": ["extra"],
                "no-match": ["other-group"],
            },
            expected_result=BaseSingleSignOnBackendResponse(
                username="guilherme.pim",
                referer=MOCK_ENTITY_ID,
                roles=["admin", "extra", "observer"],
            ),
        )


class TestSingleSignOnControllerWithSAML2(BaseSAML2Controller):
    def _test_idp_redirect_helper(
        self, expected_response, headers, status_code, expected_response_type="json"
    ):
        response = self.app.get(
            SSO_REQUEST_V1_PATH,
            headers=headers,
            expect_errors=True,
        )
        self.assertEqual(response.status_code, status_code)

        if expected_response_type == "json":
            self.assertDictEqual(response.json, expected_response)
        else:
            self.assertEqual(response.body.decode("utf-8"), expected_response)

        return response

    def test_idp_redirect_bad_referer(self):
        self._test_idp_redirect_helper(
            {
                "faultstring": "Invalid referer -- "
                "it should be either some localhost endpoint or the SSO configured entity"
            },
            {"referer": "https://hahahaha.fooled.ya"},
            http_client.BAD_REQUEST,
        )

    def test_idp_redirect(self):
        referer = {"referer": MOCK_ENTITY_ID}
        response = self._test_idp_redirect_helper(
            "", referer, http_client.TEMPORARY_REDIRECT, "text"
        )
        referer_encoded_json = re.escape(urllib.parse.quote_plus(json.dumps(referer)))
        # xample response: http://keycloak:8080/realms/stackstorm/protocol/saml?SAMLRequest=nVLLTgIxFP2VSfdjOw9gbGASlBhJUCcwunBjSqdIQ6fF3o6Rv%2FeCgtEFCzdN7sk9r7ZDC4yPu7C2c%2FXWKQjRR2sscIRHpPOWOwEaR9Eq4EHyxfhuxtMLxrfeBSedISdCcp4gAJQP2lkSTScjopuXrLlMe325ivNsIPEoilhkRRMz2c%2BSfLBM896KRE%2FKA7JGBEWQCtCpqYUgbECIpWnMBnGS10nGs4zn%2FWcSTbCGtiIcWOsQtpzSjdpJ48SGF6xg1CthWqCoIjcQnG%2FpsQ4F0WKn6nu80rbR9vV8s%2BXXEvDbuq7i6mFRk2h8bHvtLHSt8gvl37VUj%2FPZKZNxUpi1g0AFPgAFcBQBs8RQpBzihfJDWx%2FdYEIRzofYI7qJV4dVrmzQYUfKv05D%2BiO7t2D8HnnTSeWMlrt%2FGAUvLGi0IxEt9%2Bq%2Ff1P5CQ%3D%3D&RelayState=%7B%22referer%22%3A+%22http%3A%2F%2Flocalhost%22%7D
        self.assertRegex(
            response.location,
            "^"
            + MOCK_IDP_SAML_URL
            + r"\?SAMLRequest=\S+&RelayState="
            + referer_encoded_json
            + "$",
        )


class TestIdentityProviderCallbackController(BaseSAML2Controller):

    saml_response_request_id = MOCK_SAML_RESPONSE_REQUEST_ID
    saml_response = MOCK_SAML_RESPONSE

    # Helper method for similar test cases.. maybe there's a more 'table-driven' way
    # of doing this but we should be okay :)
    def _test_idp_callback_response_helper(
        self,
        expected_response,
        callback_request,
        status_code,
        expected_response_type="json",
    ):
        response = self.app.post_json(
            SSO_CALLBACK_V1_PATH, callback_request, expect_errors=True
        )
        self.assertEqual(response.status_code, status_code)

        if expected_response_type == "json":
            self.assertDictEqual(response.json, expected_response)
        else:
            self.assertEqual(response.body.decode("utf-8"), expected_response)

    # Helper method for triggering a processing of a valid SAML Response (the one from the mock :)
    def _test_idp_callback_valid_response_helper(
        self, expected_response, relay_state, status_code, expected_response_type="json"
    ):
        self._ignore_old_saml_response_setup()
        # Create a request in the database for flow to proceed properly :)
        create_web_sso_request(self.saml_response_request_id)

        self._test_idp_callback_response_helper(
            expected_response,
            {"SAMLResponse": [self.saml_response], "RelayState": relay_state},
            status_code,
            expected_response_type,
        )
        self._ignore_old_saml_response_teardown()

    def test_idp_callback_missing_response(self):
        self._test_idp_callback_response_helper(
            {"faultstring": "The SAMLResponse attribute is missing."},
            {},
            http_client.BAD_REQUEST,
        )

    def test_idp_callback_null_response(self):
        self._test_idp_callback_response_helper(
            {"faultstring": "The SAMLResponse attribute is null."},
            {"SAMLResponse": None},
            http_client.BAD_REQUEST,
        )

    def test_idp_callback_zerolen_response(self):
        self._test_idp_callback_response_helper(
            {
                "faultstring": "The SAMLResponse attribute should be a list of one or more strings"
            },
            {"SAMLResponse": []},
            http_client.BAD_REQUEST,
        )

    def test_idp_callback_nonarray_response(self):
        self._test_idp_callback_response_helper(
            {
                "faultstring": "The SAMLResponse attribute should be a list of one or more strings"
            },
            {"SAMLResponse": "test"},
            http_client.BAD_REQUEST,
        )

    def test_idp_callback_nonstring_response(self):
        self._test_idp_callback_response_helper(
            {
                "faultstring": "The SAMLResponse attribute should be a list of one or more strings"
            },
            {"SAMLResponse": [1]},
            http_client.BAD_REQUEST,
        )

    @mock.patch.object(
        saml.SAML2SingleSignOnBackend,
        "get_request_id_from_response",
        mock.MagicMock(return_value=None),
    )
    def test_idp_callback_invalid_request_id(self):
        self._test_idp_callback_response_helper(
            {"faultstring": "Invalid request id coming from SAML response"},
            {"SAMLResponse": [MOCK_SAML_RESPONSE]},
            http_client.BAD_REQUEST,
        )

    # Mock internal call to make it through
    @mock.patch.object(
        saml2.response.StatusResponse,
        "issue_instant_ok",
        mock.MagicMock(return_value=True),
    )
    def test_idp_callback_old_response(self):
        self._test_idp_callback_response_helper(
            {"faultstring": "SAML response is too old!"},
            {"SAMLResponse": [MOCK_SAML_RESPONSE]},
            http_client.BAD_REQUEST,
        )

    def test_idp_callback_empty_relay_state(self):
        self._test_idp_callback_valid_response_helper(
            {
                "faultstring": "The RelayState attribute should be a list of one or more strings"
            },
            [],
            http_client.BAD_REQUEST,
        )

    def test_idp_callback_null_relay_state(self):
        self._test_idp_callback_valid_response_helper(
            {
                "faultstring": "The RelayState attribute should be a list of one or more strings"
            },
            None,
            http_client.BAD_REQUEST,
        )

    def test_idp_callback_relay_state_missing_referer(self):
        self._test_idp_callback_valid_response_helper(
            {"faultstring": "The RelayState is missing the referer"},
            [json.dumps({})],
            http_client.BAD_REQUEST,
        )

    def test_idp_callback_relay_state_bad_referer(self):
        self._test_idp_callback_valid_response_helper(
            {
                "faultstring": "The RelayState referer [https://foobar] is not allowed. It must come from the trusted SAML entity"
            },
            [json.dumps({"referer": "https://foobar"})],
            http_client.BAD_REQUEST,
        )

    def test_idp_callback(self):
        self._test_idp_callback_valid_response_helper(
            st2auth.controllers.v1.sso.CALLBACK_SUCCESS_RESPONSE_BODY % MOCK_ENTITY_ID,
            [json.dumps({"referer": MOCK_ENTITY_ID})],
            http_client.OK,
            "str",
        )

    def test_idp_callback_invalid_authn(self):
        self.saml_response = load_fixture("saml_response_invalid.txt")
        self._test_idp_callback_valid_response_helper(
            {"faultstring": "Unable to parse the data in SAMLResponse."},
            [json.dumps({"referer": MOCK_ENTITY_ID})],
            http_client.BAD_REQUEST,
        )

    def test_idp_callback_with_relay_state(self):
        self._test_idp_callback_valid_response_helper(
            st2auth.controllers.v1.sso.CALLBACK_SUCCESS_RESPONSE_BODY % MOCK_ENTITY_ID,
            [json.dumps({"referer": MOCK_ENTITY_ID})],
            http_client.OK,
            "str",
        )
