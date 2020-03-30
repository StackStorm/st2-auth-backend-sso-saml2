# Copyright (C) 2019 Extreme Networks, Inc - All Rights Reserved
#
# Unauthorized copying of this file, via any medium is strictly
# prohibited. Proprietary and confidential. See the LICENSE file
# included with this work for details.

from __future__ import absolute_import

import json
import mock
import saml2

from oslo_config import cfg
from six.moves import http_client

import st2auth

from st2auth import app
from st2auth_sso_backends import saml
from st2common.exceptions import auth as auth_exc
from st2tests import config
from st2tests import DbTestCase
from st2tests.api import TestApp


SSO_V1_PATH = '/v1/sso'
SSO_REQUEST_V1_PATH = SSO_V1_PATH + '/request'
SSO_CALLBACK_V1_PATH = SSO_V1_PATH + '/callback'
MOCK_ENTITY_ID = 'https://127.0.0.1:3000'
MOCK_ACS_URL = '%s/auth/sso/callback' % MOCK_ENTITY_ID
MOCK_IDP_URL = 'https://some.idp.com'
MOCK_METADATA_URL = '%s/saml/metadata' % MOCK_IDP_URL
MOCK_REDIRECT_URL = '%s/app/st2/sso/saml' % MOCK_IDP_URL
MOCK_X509_CERT = 'ABCDEFG1234567890'
MOCK_REFERER = MOCK_ENTITY_ID

MOCK_SAML_METADATA_TEXT = (
    '<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor entityID="%s" xmlns:md="urn:oasis:n'
    'ames:tc:SAML:2.0:metadata"><md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSuppor'
    'tEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInf'
    'o xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>%s</ds:X509Ce'
    'rtificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:NameIDFormat>urn:oasis:names:tc:SA'
    'ML:1.1:nameid-format:unspecified</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1'
    ':nameid-format:emailAddress</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:'
    'tc:SAML:2.0:bindings:HTTP-POST" Location="%s"/><md:SingleSignOnService Binding="urn:oasis:name'
    's:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s"/></md:IDPSSODescriptor></md:EntityDescript'
    'or>'
)

MOCK_REDIRECT_INFO = {
    'headers': {
        'Location': MOCK_REDIRECT_URL
    }
}

MOCK_USER_USERNAME = 'stanley'
MOCK_USER_EMAIL = 'stanley@stackstorm.com'
MOCK_USER_LASTNAME = 'Stormin'
MOCK_USER_FIRSTNAME = 'Stanley'


class MockSamlMetadata(object):

    def __init__(self, text='foobar'):
        self.text = MOCK_SAML_METADATA_TEXT % (
            MOCK_ENTITY_ID,
            MOCK_X509_CERT,
            MOCK_REDIRECT_URL,
            MOCK_REDIRECT_URL
        )


class MockAuthnResponse(object):

    def __init__(self):
        self.ava = {
            'Username': MOCK_USER_USERNAME,
            'Email': MOCK_USER_EMAIL,
            'LastName': MOCK_USER_LASTNAME,
            'FirstName': MOCK_USER_FIRSTNAME
        }


class BaseSAML2Controller(DbTestCase):

    @classmethod
    def setUpClass(cls, **kwargs):
        super(BaseSAML2Controller, cls).setUpClass()

        config.parse_args()

        sso_backend_kwargs = {'metadata_url': MOCK_METADATA_URL, 'entity_id': MOCK_ENTITY_ID}
        kwargs_json = json.dumps(sso_backend_kwargs)
        cfg.CONF.set_override(name='sso', override=True, group='auth')
        cfg.CONF.set_override(name='sso_backend', override='saml2', group='auth')
        cfg.CONF.set_override(name='sso_backend_kwargs', override=kwargs_json, group='auth')

        with mock.patch('requests.get') as mock_requests_get:
            mock_requests_get.return_value = MockSamlMetadata()
            cls.app = TestApp(app.setup_app(), **kwargs)


class TestSingleSignOnControllerWithSAML2(BaseSAML2Controller):

    def test_cls_init(self):
        # Delay import here otherwise setupClass will not have run.
        from st2auth.controllers.v1 import sso as sso_api_controller
        instance = sso_api_controller.SSO_BACKEND

        self.assertEqual(instance.entity_id, MOCK_ENTITY_ID)
        self.assertIsNotNone(instance.relay_state_id)
        self.assertEqual(instance.https_acs_url, MOCK_ACS_URL)
        self.assertEqual(instance.saml_metadata_url, MOCK_METADATA_URL)

        expected_saml_client_settings = {
            'entityid': MOCK_ENTITY_ID,
            'metadata': {'inline': [MockSamlMetadata().text]},
            'service': {
                'sp': {
                    'endpoints': {
                        'assertion_consumer_service': [
                            (MOCK_ACS_URL, saml2.BINDING_HTTP_REDIRECT),
                            (MOCK_ACS_URL, saml2.BINDING_HTTP_POST)
                        ]
                    },
                    'allow_unsolicited': True,
                    'authn_requests_signed': False,
                    'logout_requests_signed': True,
                    'want_assertions_signed': True,
                    'want_response_signed': True
                }
            }
        }

        self.assertDictEqual(instance.saml_client_settings, expected_saml_client_settings)

    @mock.patch.object(
        saml.SAML2SingleSignOnBackend,
        '_handle_verification_error',
        mock.MagicMock(side_effect=auth_exc.SSOVerificationError('See unit test.')))
    def test_idp_redirect_bad_referer(self):
        headers = {'referer': 'https://hahahaha.fooled.ya'}
        expected_error = {'faultstring': 'Internal Server Error'}
        expected_msg = 'Invalid referer.'
        response = self.app.get(SSO_REQUEST_V1_PATH, headers=headers, expect_errors=True)
        self.assertTrue(response.status_code, http_client.INTERNAL_SERVER_ERROR)
        self.assertDictEqual(response.json, expected_error)
        self.assertTrue(saml.SAML2SingleSignOnBackend._handle_verification_error.called)
        saml.SAML2SingleSignOnBackend._handle_verification_error.assert_called_with(expected_msg)

    @mock.patch.object(
        saml2.client.Saml2Client,
        'prepare_for_authenticate',
        mock.MagicMock(return_value=(None, MOCK_REDIRECT_INFO)))
    def test_idp_redirect(self):
        headers = {'referer': MOCK_ENTITY_ID}
        response = self.app.get(SSO_REQUEST_V1_PATH, headers=headers, expect_errors=False)
        self.assertTrue(response.status_code, http_client.TEMPORARY_REDIRECT)
        self.assertEqual(response.location, MOCK_REDIRECT_URL)


class TestIdentityProviderCallbackController(BaseSAML2Controller):

    @mock.patch.object(
        saml.SAML2SingleSignOnBackend,
        '_handle_verification_error',
        mock.MagicMock(side_effect=auth_exc.SSOVerificationError('See unit test.')))
    def test_idp_callback_missing_response(self):
        expected_error = {'faultstring': 'Error encountered while verifying the SAML2 response.'}
        expected_msg = 'The SAMLResponse attribute is missing.'
        response = self.app.post_json(SSO_CALLBACK_V1_PATH, {}, expect_errors=True)
        self.assertTrue(response.status_code, http_client.UNAUTHORIZED)
        self.assertDictEqual(response.json, expected_error)
        self.assertTrue(saml.SAML2SingleSignOnBackend._handle_verification_error.called)
        saml.SAML2SingleSignOnBackend._handle_verification_error.assert_called_with(expected_msg)

    @mock.patch.object(
        saml.SAML2SingleSignOnBackend,
        '_handle_verification_error',
        mock.MagicMock(side_effect=auth_exc.SSOVerificationError('See unit test.')))
    def test_idp_callback_null_response(self):
        expected_error = {'faultstring': 'Error encountered while verifying the SAML2 response.'}
        expected_msg = 'The SAMLResponse attribute is null.'
        saml_response = {'SAMLResponse': None}
        response = self.app.post_json(SSO_CALLBACK_V1_PATH, saml_response, expect_errors=True)
        self.assertTrue(response.status_code, http_client.UNAUTHORIZED)
        self.assertDictEqual(response.json, expected_error)
        self.assertTrue(saml.SAML2SingleSignOnBackend._handle_verification_error.called)
        saml.SAML2SingleSignOnBackend._handle_verification_error.assert_called_with(expected_msg)

    @mock.patch.object(
        saml.SAML2SingleSignOnBackend,
        '_handle_verification_error',
        mock.MagicMock(side_effect=auth_exc.SSOVerificationError('See unit test.')))
    def test_idp_callback_empty_response(self):
        expected_error = {'faultstring': 'Error encountered while verifying the SAML2 response.'}
        expected_msg = 'The SAMLResponse attribute is empty.'
        saml_response = {'SAMLResponse': []}
        response = self.app.post_json(SSO_CALLBACK_V1_PATH, saml_response, expect_errors=True)
        self.assertTrue(response.status_code, http_client.UNAUTHORIZED)
        self.assertDictEqual(response.json, expected_error)
        self.assertTrue(saml.SAML2SingleSignOnBackend._handle_verification_error.called)
        saml.SAML2SingleSignOnBackend._handle_verification_error.assert_called_with(expected_msg)

    @mock.patch.object(
        saml.SAML2SingleSignOnBackend,
        '_handle_verification_error',
        mock.MagicMock(side_effect=auth_exc.SSOVerificationError('See unit test.')))
    def test_idp_callback_null_relay_state(self):
        expected_error = {'faultstring': 'Error encountered while verifying the SAML2 response.'}
        expected_msg = 'The RelayState attribute is null.'
        saml_response = {'SAMLResponse': ['1234567890ABCDEFG'], 'RelayState': None}
        response = self.app.post_json(SSO_CALLBACK_V1_PATH, saml_response, expect_errors=True)
        self.assertTrue(response.status_code, http_client.UNAUTHORIZED)
        self.assertDictEqual(response.json, expected_error)
        self.assertTrue(saml.SAML2SingleSignOnBackend._handle_verification_error.called)
        saml.SAML2SingleSignOnBackend._handle_verification_error.assert_called_with(expected_msg)

    @mock.patch.object(
        saml.SAML2SingleSignOnBackend,
        '_handle_verification_error',
        mock.MagicMock(side_effect=auth_exc.SSOVerificationError('See unit test.')))
    def test_idp_callback_empty_relay_state(self):
        expected_error = {'faultstring': 'Error encountered while verifying the SAML2 response.'}
        expected_msg = 'The RelayState attribute is empty.'
        saml_response = {'SAMLResponse': ['1234567890ABCDEFG'], 'RelayState': []}
        response = self.app.post_json(SSO_CALLBACK_V1_PATH, saml_response, expect_errors=True)
        self.assertTrue(response.status_code, http_client.UNAUTHORIZED)
        self.assertDictEqual(response.json, expected_error)
        self.assertTrue(saml.SAML2SingleSignOnBackend._handle_verification_error.called)
        saml.SAML2SingleSignOnBackend._handle_verification_error.assert_called_with(expected_msg)

    @mock.patch.object(
        saml.SAML2SingleSignOnBackend,
        '_handle_verification_error',
        mock.MagicMock(side_effect=auth_exc.SSOVerificationError('See unit test.')))
    def test_idp_callback_relay_state_missing_id(self):
        expected_error = {'faultstring': 'Error encountered while verifying the SAML2 response.'}
        expected_msg = 'The value of the RelayState in the response does not match.'
        relay_state = json.dumps({'referer': MOCK_REFERER})
        saml_response = {'SAMLResponse': ['1234567890ABCDEFG'], 'RelayState': [relay_state]}
        response = self.app.post_json(SSO_CALLBACK_V1_PATH, saml_response, expect_errors=True)
        self.assertTrue(response.status_code, http_client.UNAUTHORIZED)
        self.assertDictEqual(response.json, expected_error)
        self.assertTrue(saml.SAML2SingleSignOnBackend._handle_verification_error.called)
        saml.SAML2SingleSignOnBackend._handle_verification_error.assert_called_with(expected_msg)

    @mock.patch.object(
        saml.SAML2SingleSignOnBackend,
        '_handle_verification_error',
        mock.MagicMock(side_effect=auth_exc.SSOVerificationError('See unit test.')))
    def test_idp_callback_relay_state_bad_id(self):
        expected_error = {'faultstring': 'Error encountered while verifying the SAML2 response.'}
        expected_msg = 'The value of the RelayState in the response does not match.'
        relay_state = json.dumps({'id': 'foobar', 'referer': MOCK_REFERER})
        saml_response = {'SAMLResponse': ['1234567890ABCDEFG'], 'RelayState': [relay_state]}
        response = self.app.post_json(SSO_CALLBACK_V1_PATH, saml_response, expect_errors=True)
        self.assertTrue(response.status_code, http_client.UNAUTHORIZED)
        self.assertDictEqual(response.json, expected_error)
        self.assertTrue(saml.SAML2SingleSignOnBackend._handle_verification_error.called)
        saml.SAML2SingleSignOnBackend._handle_verification_error.assert_called_with(expected_msg)

    @mock.patch.object(
        saml.SAML2SingleSignOnBackend,
        '_get_relay_state_id',
        mock.MagicMock(return_value='12345'))
    @mock.patch.object(
        saml.SAML2SingleSignOnBackend,
        '_handle_verification_error',
        mock.MagicMock(side_effect=auth_exc.SSOVerificationError('See unit test.')))
    def test_idp_callback_relay_state_missing_referer(self):
        expected_error = {'faultstring': 'Error encountered while verifying the SAML2 response.'}
        expected_msg = 'The value of the RelayState in the response does not match.'
        relay_state = json.dumps({'id': '12345'})
        saml_response = {'SAMLResponse': ['1234567890ABCDEFG'], 'RelayState': [relay_state]}
        response = self.app.post_json(SSO_CALLBACK_V1_PATH, saml_response, expect_errors=True)
        self.assertTrue(response.status_code, http_client.UNAUTHORIZED)
        self.assertDictEqual(response.json, expected_error)
        self.assertTrue(saml.SAML2SingleSignOnBackend._handle_verification_error.called)
        saml.SAML2SingleSignOnBackend._handle_verification_error.assert_called_with(expected_msg)

    @mock.patch.object(
        saml.SAML2SingleSignOnBackend,
        '_get_relay_state_id',
        mock.MagicMock(return_value='12345'))
    @mock.patch.object(
        saml.SAML2SingleSignOnBackend,
        '_handle_verification_error',
        mock.MagicMock(side_effect=auth_exc.SSOVerificationError('See unit test.')))
    def test_idp_callback_relay_state_bad_referer(self):
        expected_error = {'faultstring': 'Error encountered while verifying the SAML2 response.'}
        expected_msg = 'The value of the RelayState in the response does not match.'
        relay_state = json.dumps({'id': '12345', 'referer': 'https://foobar'})
        saml_response = {'SAMLResponse': ['1234567890ABCDEFG'], 'RelayState': [relay_state]}
        response = self.app.post_json(SSO_CALLBACK_V1_PATH, saml_response, expect_errors=True)
        self.assertTrue(response.status_code, http_client.UNAUTHORIZED)
        self.assertDictEqual(response.json, expected_error)
        self.assertTrue(saml.SAML2SingleSignOnBackend._handle_verification_error.called)
        saml.SAML2SingleSignOnBackend._handle_verification_error.assert_called_with(expected_msg)

    @mock.patch.object(
        saml2.client.Saml2Client,
        'parse_authn_request_response',
        mock.MagicMock(return_value=MockAuthnResponse()))
    def test_idp_callback(self):
        saml_response = {'SAMLResponse': ['1234567890ABCDEFG']}
        expected_body = st2auth.controllers.v1.sso.CALLBACK_SUCCESS_RESPONSE_BODY % MOCK_REFERER
        response = self.app.post_json(SSO_CALLBACK_V1_PATH, saml_response, expect_errors=False)
        self.assertTrue(response.status_code, http_client.OK)
        self.assertEqual(expected_body, response.body.decode('utf-8'))

    @mock.patch.object(
        saml.SAML2SingleSignOnBackend,
        '_get_relay_state_id',
        mock.MagicMock(return_value='12345'))
    @mock.patch.object(
        saml2.client.Saml2Client,
        'parse_authn_request_response',
        mock.MagicMock(return_value=MockAuthnResponse()))
    def test_idp_callback_with_relay_state(self):
        relay_state = json.dumps({'id': '12345', 'referer': MOCK_REFERER})
        saml_response = {'SAMLResponse': ['1234567890ABCDEFG'], 'RelayState': [relay_state]}
        expected_body = st2auth.controllers.v1.sso.CALLBACK_SUCCESS_RESPONSE_BODY % MOCK_REFERER
        response = self.app.post_json(SSO_CALLBACK_V1_PATH, saml_response, expect_errors=False)
        self.assertTrue(response.status_code, http_client.OK)
        self.assertEqual(expected_body, response.body.decode('utf-8'))
