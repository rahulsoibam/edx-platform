import unittest
from django.conf import settings
from django.http import HttpRequest
from django.test import TestCase

from student.tests.factories import UserFactory


OAUTH_PROVIDER_ENABLED = settings.FEATURES.get('ENABLE_OAUTH2_PROVIDER')
if OAUTH_PROVIDER_ENABLED:
    from openedx.core.djangoapps.oauth_dispatch import api
    from openedx.core.djangoapps.oauth_dispatch.adapters import DOTAdapter
    from openedx.core.djangoapps.oauth_dispatch.tests.constants import DUMMY_REDIRECT_URL


@unittest.skipUnless(OAUTH_PROVIDER_ENABLED, 'OAuth2 not enabled')
class TestOAuthDispatchAPI(TestCase):
    def setUp(self):
        super(TestOAuthDispatchAPI, self).setUp()
        self.adapter = DOTAdapter()
        self.user = UserFactory()
        self.client = self.adapter.create_public_client(
            name='public app',
            user=self.user,
            redirect_uri=DUMMY_REDIRECT_URL,
            client_id='public-client-id',
        )
        self.request = HttpRequest()

    def test_create_token_success(self):
        token = api.create_dot_access_token(self.request, self.user, self.client)
        self.assertTrue(token['access_token'])
        self.assertTrue(token['refresh_token'])
        self.assertDictContainsSubset(
            {
                u'token_type': u'Bearer',
                u'expires_in': 36000,
                u'scope': u'default',
            },
            token,
        )

    def test_refresh_token_success(self):
        token = api.create_dot_access_token(self.request, self.user, self.client)
        new_token = api.refresh_dot_access_token(self.request, self.user, self.client.client_id, token['refresh_token'])
        self.assertDictContainsSubset(
            {
                u'token_type': u'Bearer',
                u'expires_in': 36000,
                u'scope': u'default',
            },
            new_token,
        )
        self.assertNotEqual(token['access_token'], new_token['access_token'])
        self.assertNotEqual(token['refresh_token'], new_token['refresh_token'])


    def test_refresh_token_invalid_client(self):
        token = api.create_dot_access_token(self.request, self.user, self.client)
        with self.assertRaises(api.OAuth2Error) as error:
            new_token = api.refresh_dot_access_token(
                self.request, self.user, 'invalid_client_id', token['refresh_token'],
            )
        self.assertIn('invalid_client', error.exception.description)


    def test_refresh_token_invalid_token(self):
        token = api.create_dot_access_token(self.request, self.user, self.client)
        with self.assertRaises(api.OAuth2Error) as error:
            new_token = api.refresh_dot_access_token(
                self.request, self.user, self.client.client_id, 'invalid_refresh_token',
            )
        self.assertIn('invalid_grant', error.exception.description)
