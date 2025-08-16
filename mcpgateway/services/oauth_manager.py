# -*- coding: utf-8 -*-
"""OAuth 2.0 Manager for MCP Gateway.

This module handles OAuth 2.0 authentication flows including:
- Client Credentials (Machine-to-Machine)
- Authorization Code (User Delegation)
"""

import logging
from typing import Dict, Any, Optional
from oauthlib.oauth2 import BackendApplicationClient, WebApplicationClient
from requests_oauthlib import OAuth2Session
import aiohttp
import asyncio

logger = logging.getLogger(__name__)


class OAuthManager:
    """Manages OAuth 2.0 authentication flows."""

    def __init__(self, request_timeout: int = 30, max_retries: int = 3):
        """Initialize OAuth Manager.

        Args:
            request_timeout: Timeout for OAuth requests in seconds
            max_retries: Maximum number of retry attempts for token requests
        """
        self.request_timeout = request_timeout
        self.max_retries = max_retries

    async def get_access_token(
        self,
        credentials: Dict[str, Any]
    ) -> str:
        """Get access token based on grant type.

        Args:
            credentials: OAuth configuration containing grant_type and other params

        Returns:
            Access token string

        Raises:
            ValueError: If grant type is unsupported
            OAuthError: If token acquisition fails
        """
        grant_type = credentials.get('grant_type')
        print(f"grant_type: {grant_type}")

        if grant_type == 'client_credentials':
            return await self._client_credentials_flow(credentials)
        elif grant_type == 'authorization_code':
            # For authorization code flow, this method should not be called directly
            # Use get_authorization_url and exchange_code_for_token instead
            raise ValueError(
                "Authorization code flow requires calling get_authorization_url first"
            )
        else:
            raise ValueError(f"Unsupported grant type: {grant_type}")

    async def _client_credentials_flow(
        self,
        credentials: Dict[str, Any]
    ) -> str:
        """Machine-to-machine authentication using client credentials.

        Args:
            credentials: OAuth configuration with client_id, client_secret, token_url

        Returns:
            Access token string
        """
        client_id = credentials['client_id']
        client_secret = credentials['client_secret']
        token_url = credentials['token_url']
        scopes = credentials.get('scopes', [])

        # Create OAuth2 session with backend application client
        client = BackendApplicationClient(client_id=client_id)
        oauth = OAuth2Session(client=client)

        # Prepare token request data
        token_data = {
            'grant_type': 'client_credentials',
            'client_id': client_id,
            'client_secret': client_secret,
        }

        if scopes:
            token_data['scope'] = ' '.join(scopes) if isinstance(scopes, list) else scopes

        # Fetch token with retries
        for attempt in range(self.max_retries):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        token_url,
                        data=token_data,
                        timeout=aiohttp.ClientTimeout(total=self.request_timeout)
                    ) as response:
                        response.raise_for_status()
                        token_response = await response.json()

                        if 'access_token' not in token_response:
                            raise OAuthError(
                                f"No access_token in response: {token_response}"
                            )

                        logger.info(
                            f"Successfully obtained access token via client credentials"
                        )
                        return token_response['access_token']

            except aiohttp.ClientError as e:
                logger.warning(
                    f"Token request attempt {attempt + 1} failed: {str(e)}"
                )
                if attempt == self.max_retries - 1:
                    raise OAuthError(
                        f"Failed to obtain access token after {self.max_retries} attempts: {str(e)}"
                    )
                await asyncio.sleep(2 ** attempt)  # Exponential backoff

    async def get_authorization_url(
        self,
        credentials: Dict[str, Any]
    ) -> Dict[str, str]:
        """Get authorization URL for user delegation flow.

        Args:
            credentials: OAuth configuration with client_id, authorization_url, etc.

        Returns:
            Dict containing authorization_url and state
        """
        client_id = credentials['client_id']
        redirect_uri = credentials['redirect_uri']
        authorization_url = credentials['authorization_url']
        scopes = credentials.get('scopes', [])

        # Create OAuth2 session
        oauth = OAuth2Session(
            client_id,
            redirect_uri=redirect_uri,
            scope=scopes
        )

        # Generate authorization URL with state for CSRF protection
        auth_url, state = oauth.authorization_url(authorization_url)

        logger.info(f"Generated authorization URL for client {client_id}")

        return {
            'authorization_url': auth_url,
            'state': state
        }

    async def exchange_code_for_token(
        self,
        credentials: Dict[str, Any],
        code: str,
        state: str
    ) -> str:
        """Exchange authorization code for access token.

        Args:
            credentials: OAuth configuration
            code: Authorization code from callback
            state: State parameter for CSRF validation

        Returns:
            Access token string
        """
        client_id = credentials['client_id']
        client_secret = credentials['client_secret']
        token_url = credentials['token_url']
        redirect_uri = credentials['redirect_uri']

        # Prepare token exchange data
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'client_id': client_id,
            'client_secret': client_secret,
        }

        # Exchange code for token with retries
        for attempt in range(self.max_retries):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        token_url,
                        data=token_data,
                        timeout=aiohttp.ClientTimeout(total=self.request_timeout)
                    ) as response:
                        response.raise_for_status()
                        token_response = await response.json()

                        if 'access_token' not in token_response:
                            raise OAuthError(
                                f"No access_token in response: {token_response}"
                            )

                        logger.info(
                            f"Successfully exchanged authorization code for access token"
                        )
                        return token_response['access_token']

            except aiohttp.ClientError as e:
                logger.warning(
                    f"Token exchange attempt {attempt + 1} failed: {str(e)}"
                )
                if attempt == self.max_retries - 1:
                    raise OAuthError(
                        f"Failed to exchange code for token after {self.max_retries} attempts: {str(e)}"
                    )
                await asyncio.sleep(2 ** attempt)  # Exponential backoff


class OAuthError(Exception):
    """OAuth-related errors."""
    pass
