# -*- coding: utf-8 -*-
"""Unit tests for OAuth Manager."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from mcpgateway.services.oauth_manager import OAuthManager, OAuthError


class TestOAuthManager:
    """Test cases for OAuthManager class."""

    def test_init(self):
        """Test OAuthManager initialization."""
        manager = OAuthManager(request_timeout=45, max_retries=5)
        assert manager.request_timeout == 45
        assert manager.max_retries == 5

    def test_init_defaults(self):
        """Test OAuthManager initialization with defaults."""
        manager = OAuthManager()
        assert manager.request_timeout == 30
        assert manager.max_retries == 3

    @pytest.mark.asyncio
    async def test_get_access_token_client_credentials_success(self):
        """Test successful client credentials flow."""
        manager = OAuthManager()
        credentials = {
            "grant_type": "client_credentials",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "token_url": "https://oauth.example.com/token",
            "scopes": ["read", "write"]
        }

        with patch('mcpgateway.services.oauth_manager.aiohttp.ClientSession') as mock_session:
            mock_session.return_value.__aenter__.return_value.post.return_value.__aenter__.return_value = MagicMock(
                status=200,
                json=AsyncMock(return_value={"access_token": "test_token_123"}),
                raise_for_status=MagicMock()
            )

            result = await manager.get_access_token(credentials)
            assert result == "test_token_123"

    @pytest.mark.asyncio
    async def test_get_access_token_unsupported_grant_type(self):
        """Test error handling for unsupported grant type."""
        manager = OAuthManager()
        credentials = {
            "grant_type": "unsupported",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "token_url": "https://oauth.example.com/token"
        }

        with pytest.raises(ValueError, match="Unsupported grant type: unsupported"):
            await manager.get_access_token(credentials)

    @pytest.mark.asyncio
    async def test_get_access_token_authorization_code_error(self):
        """Test error when calling get_access_token with authorization code flow."""
        manager = OAuthManager()
        credentials = {
            "grant_type": "authorization_code",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "token_url": "https://oauth.example.com/token"
        }

        with pytest.raises(ValueError, match="Authorization code flow requires calling get_authorization_url first"):
            await manager.get_access_token(credentials)

    @pytest.mark.asyncio
    async def test_get_authorization_url_success(self):
        """Test successful authorization URL generation."""
        manager = OAuthManager()
        credentials = {
            "client_id": "test_client",
            "redirect_uri": "https://gateway.example.com/callback",
            "authorization_url": "https://oauth.example.com/authorize",
            "scopes": ["read", "write"]
        }

        result = await manager.get_authorization_url(credentials)

        assert "authorization_url" in result
        assert "state" in result
        assert "https://oauth.example.com/authorize" in result["authorization_url"]
        assert result["state"] is not None

    @pytest.mark.asyncio
    async def test_exchange_code_for_token_success(self):
        """Test successful code exchange for token."""
        manager = OAuthManager()
        credentials = {
            "client_id": "test_client",
            "client_secret": "test_secret",
            "token_url": "https://oauth.example.com/token",
            "redirect_uri": "https://gateway.example.com/callback"
        }

        with patch('mcpgateway.services.oauth_manager.aiohttp.ClientSession') as mock_session:
            mock_session.return_value.__aenter__.return_value.post.return_value.__aenter__.return_value = MagicMock(
                status=200,
                json=AsyncMock(return_value={"access_token": "exchanged_token_456"}),
                raise_for_status=MagicMock()
            )

            result = await manager.exchange_code_for_token(credentials, "auth_code_123", "state_456")
            assert result == "exchanged_token_456"

    @pytest.mark.asyncio
    async def test_client_credentials_flow_retry_on_failure(self):
        """Test retry mechanism for client credentials flow."""
        manager = OAuthManager(max_retries=2)
        credentials = {
            "grant_type": "client_credentials",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "token_url": "https://oauth.example.com/token"
        }

        with patch('mcpgateway.services.oauth_manager.aiohttp.ClientSession') as mock_session:
            # First attempt fails, second succeeds
            mock_response = MagicMock()
            mock_response.status = 500
            mock_response.raise_for_status.side_effect = [Exception("First failure"), None]
            mock_response.json = AsyncMock(return_value={"access_token": "retry_token"})

            mock_session.return_value.__aenter__.return_value.post.return_value.__aenter__.return_value = mock_response

            result = await manager.get_access_token(credentials)
            assert result == "retry_token"

    @pytest.mark.asyncio
    async def test_client_credentials_flow_max_retries_exceeded(self):
        """Test that max retries are respected."""
        manager = OAuthManager(max_retries=2)
        credentials = {
            "grant_type": "client_credentials",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "token_url": "https://oauth.example.com/token"
        }

        with patch('mcpgateway.services.oauth_manager.aiohttp.ClientSession') as mock_session:
            mock_response = MagicMock()
            mock_response.status = 500
            mock_response.raise_for_status.side_effect = Exception("Always fails")

            mock_session.return_value.__aenter__.return_value.post.return_value.__aenter__.return_value = mock_response

            with pytest.raises(OAuthError, match="Failed to obtain access token after 2 attempts"):
                await manager.get_access_token(credentials)

    def test_oauth_error_inheritance(self):
        """Test that OAuthError inherits from Exception."""
        error = OAuthError("Test error")
        assert isinstance(error, Exception)
        assert str(error) == "Test error"
