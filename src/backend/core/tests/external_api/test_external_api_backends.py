"""
Tests for the resource server backend authenticating with HTTP Basic.
"""

import base64

import pytest
import responses
from responses import matchers
from rest_framework.test import APIClient

from core.tests.conftest import resource_server_backend_setup
from core.tests.utils.urls import reload_urls

pytestmark = pytest.mark.django_db

# pylint: disable=unused-argument


INTROSPECTION_RESPONSE = {
    "sub": "very-specific-sub",
    "client_id": "some_service_provider",
    "scope": "openid groups",
    "active": True,
}


@pytest.fixture(name="basic_auth_resource_server")
def fixture_basic_auth_resource_server(settings):
    """Resource server configured with the HTTP Basic backend."""
    resource_server_backend_setup(settings)
    settings.OIDC_RS_BACKEND_CLASS = (
        "core.external_api.backends.BasicAuthResourceServerBackend"
    )
    reload_urls()


def test_external_api_basic_auth_backend_introspects_with_http_basic(
    basic_auth_resource_server, user_token, user_specific_sub
):
    """
    The backend SHOULD send its client credentials in an HTTP Basic header,
    not in the request body, and authenticate the introspected user.
    """
    expected_authorization = "Basic " + base64.b64encode(
        b"some_client_id:some_client_secret"
    ).decode("ascii")

    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.POST,
            "https://oidc.example.com/introspect",
            json=INTROSPECTION_RESPONSE,
            match=[
                matchers.header_matcher({"Authorization": expected_authorization}),
                # Exactly the token: no client_id or client_secret in the body
                matchers.urlencoded_params_matcher({"token": "some_token"}),
            ],
        )

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {user_token}")
        response = client.get("/external_api/v1.0/users/me/")

    assert response.status_code == 200
    assert response.json()["id"] == str(user_specific_sub.id)


def test_external_api_basic_auth_backend_rejected_credentials(
    basic_auth_resource_server, user_token, user_specific_sub
):
    """
    A request SHOULD NOT be authenticated when the authorization server
    rejects the client credentials. As with the default backend, a failed
    introspection call is a SuspiciousOperation, answered with a 400.
    """
    with responses.RequestsMock() as rsps:
        rsps.add(responses.POST, "https://oidc.example.com/introspect", status=401)

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {user_token}")
        response = client.get("/external_api/v1.0/users/me/")

    assert response.status_code == 400
