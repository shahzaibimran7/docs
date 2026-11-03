"""Resource server backends for the Docs external API."""

import requests
from lasuite.oidc_resource_server.backend import ResourceServerBackend
from lasuite.oidc_resource_server.clients import AuthorizationServerClient


class BasicAuthAuthorizationServerClient(AuthorizationServerClient):
    """
    Authorization server client authenticating with HTTP Basic.

    The default client sends its credentials in the request body
    ("client_secret_post"). Some authorization servers, such as the menshen
    token exchange server, only accept HTTP Basic ("client_secret_basic",
    RFC 6749 section 2.3.1) on their introspection endpoint.
    """

    def get_introspection(self, client_id, client_secret, token):
        """Retrieve introspection response about a token."""
        response = requests.post(
            self._url_introspection,
            data={"token": token},
            auth=(client_id, client_secret),
            headers=self._introspection_headers,
            verify=self._verify_ssl,
            timeout=self._timeout,
            proxies=self._proxy,
        )
        response.raise_for_status()
        return response.text


class BasicAuthResourceServerBackend(ResourceServerBackend):
    """
    Resource server backend introspecting tokens with HTTP Basic client authentication.

    Enable with:
    OIDC_RS_BACKEND_CLASS=core.external_api.backends.BasicAuthResourceServerBackend
    """

    authorization_server_client_class = BasicAuthAuthorizationServerClient
