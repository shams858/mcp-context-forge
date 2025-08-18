# -*- coding: utf-8 -*-
"""OAuth Token Storage Service for MCP Gateway.

This module handles the storage, retrieval, and management of OAuth access and refresh tokens
for Authorization Code flow implementations.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import select

from mcpgateway.db import OAuthToken, Gateway
from mcpgateway.utils.oauth_encryption import get_oauth_encryption
from mcpgateway.services.oauth_manager import OAuthError

logger = logging.getLogger(__name__)


class TokenStorageService:
    """Manages OAuth token storage and retrieval."""

    def __init__(self, db: Session):
        """Initialize Token Storage Service.

        Args:
            db: Database session
        """
        self.db = db
        try:
            from mcpgateway.config import get_settings
            settings = get_settings()
            self.encryption = get_oauth_encryption(settings.auth_encryption_secret)
        except (ImportError, AttributeError):
            logger.warning("OAuth encryption not available, using plain text storage")
            self.encryption = None

    async def store_tokens(
        self,
        gateway_id: str,
        user_id: str,
        access_token: str,
        refresh_token: Optional[str],
        expires_in: int,
        scopes: List[str]
    ) -> OAuthToken:
        """Store OAuth tokens for a gateway-user combination.

        Args:
            gateway_id: ID of the gateway
            user_id: OAuth provider user ID
            access_token: Access token from OAuth provider
            refresh_token: Refresh token from OAuth provider (optional)
            expires_in: Token expiration time in seconds
            scopes: List of OAuth scopes granted

        Returns:
            OAuthToken record

        Raises:
            OAuthError: If token storage fails
        """
        try:
            # Encrypt sensitive tokens if encryption is available
            encrypted_access = access_token
            encrypted_refresh = refresh_token

            if self.encryption:
                encrypted_access = self.encryption.encrypt_secret(access_token)
                if refresh_token:
                    encrypted_refresh = self.encryption.encrypt_secret(refresh_token)

            # Calculate expiration
            expires_at = datetime.utcnow() + timedelta(seconds=expires_in)

            # Create or update token record
            token_record = self.db.execute(
                select(OAuthToken).where(
                    OAuthToken.gateway_id == gateway_id,
                    OAuthToken.user_id == user_id
                )
            ).scalar_one_or_none()

            if token_record:
                # Update existing record
                token_record.access_token = encrypted_access
                token_record.refresh_token = encrypted_refresh
                token_record.expires_at = expires_at
                token_record.scopes = scopes
                token_record.updated_at = datetime.utcnow()
                logger.info(f"Updated OAuth tokens for gateway {gateway_id}, user {user_id}")
            else:
                # Create new record
                token_record = OAuthToken(
                    gateway_id=gateway_id,
                    user_id=user_id,
                    access_token=encrypted_access,
                    refresh_token=encrypted_refresh,
                    expires_at=expires_at,
                    scopes=scopes
                )
                self.db.add(token_record)
                logger.info(f"Stored new OAuth tokens for gateway {gateway_id}, user {user_id}")

            self.db.commit()
            return token_record

        except Exception as e:
            self.db.rollback()
            logger.error(f"Failed to store OAuth tokens: {str(e)}")
            raise OAuthError(f"Token storage failed: {str(e)}")

    async def get_valid_token(
        self,
        gateway_id: str,
        user_id: str,
        threshold_seconds: int = 300
    ) -> Optional[str]:
        """Get a valid access token, refreshing if necessary.

        Args:
            gateway_id: ID of the gateway
            user_id: OAuth provider user ID
            threshold_seconds: Seconds before expiry to consider token expired

        Returns:
            Valid access token or None if no valid token available
        """
        try:
            token_record = self.db.execute(
                select(OAuthToken).where(
                    OAuthToken.gateway_id == gateway_id,
                    OAuthToken.user_id == user_id
                )
            ).scalar_one_or_none()

            if not token_record:
                logger.debug(f"No OAuth tokens found for gateway {gateway_id}, user {user_id}")
                return None

            # Check if token is expired or near expiration
            if self._is_token_expired(token_record, threshold_seconds):
                logger.info(f"OAuth token expired for gateway {gateway_id}, user {user_id}")
                if token_record.refresh_token:
                    # Attempt to refresh token
                    new_token = await self._refresh_access_token(token_record)
                    if new_token:
                        return new_token
                return None

            # Decrypt and return valid token
            if self.encryption:
                return self.encryption.decrypt_secret(token_record.access_token)
            else:
                return token_record.access_token

        except Exception as e:
            logger.error(f"Failed to retrieve OAuth token: {str(e)}")
            return None

    async def get_any_valid_token(
        self,
        gateway_id: str,
        threshold_seconds: int = 300
    ) -> Optional[str]:
        """Get any valid access token for a gateway, regardless of user.

        Args:
            gateway_id: ID of the gateway
            threshold_seconds: Seconds before expiry to consider token expired

        Returns:
            Valid access token or None if no valid token available
        """
        try:
            # Get any token for this gateway
            token_record = self.db.execute(
                select(OAuthToken).where(
                    OAuthToken.gateway_id == gateway_id
                )
            ).scalar_one_or_none()

            if not token_record:
                logger.debug(f"No OAuth tokens found for gateway {gateway_id}")
                return None

            # Check if token is expired or near expiration
            if self._is_token_expired(token_record, threshold_seconds):
                logger.info(f"OAuth token expired for gateway {gateway_id}")
                if token_record.refresh_token:
                    # Attempt to refresh token
                    new_token = await self._refresh_access_token(token_record)
                    if new_token:
                        return new_token
                return None

            # Decrypt and return valid token
            if self.encryption:
                return self.encryption.decrypt_secret(token_record.access_token)
            else:
                return token_record.access_token

        except Exception as e:
            logger.error(f"Failed to retrieve OAuth token: {str(e)}")
            return None

    async def _refresh_access_token(self, token_record: OAuthToken) -> Optional[str]:
        """Refresh an expired access token using refresh token.

        Args:
            token_record: OAuth token record to refresh

        Returns:
            New access token or None if refresh failed
        """
        try:
            # This is a placeholder for token refresh implementation
            # In a real implementation, you would:
            # 1. Decrypt the refresh token
            # 2. Make a request to the OAuth provider's token endpoint
            # 3. Update the stored tokens with the new response
            # 4. Return the new access token

            logger.info(f"Token refresh not yet implemented for gateway {token_record.gateway_id}")
            return None

        except Exception as e:
            logger.error(f"Failed to refresh OAuth token: {str(e)}")
            return None

    def _is_token_expired(self, token_record: OAuthToken, threshold_seconds: int = 300) -> bool:
        """Check if token is expired or near expiration.

        Args:
            token_record: OAuth token record to check
            threshold_seconds: Seconds before expiry to consider token expired

        Returns:
            True if token is expired or near expiration
        """
        if not token_record.expires_at:
            return True

        return datetime.utcnow() + timedelta(seconds=threshold_seconds) >= token_record.expires_at

    async def get_token_info(
        self,
        gateway_id: str,
        user_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get information about stored OAuth tokens.

        Args:
            gateway_id: ID of the gateway
            user_id: OAuth provider user ID

        Returns:
            Token information dictionary or None if not found
        """
        try:
            token_record = self.db.execute(
                select(OAuthToken).where(
                    OAuthToken.gateway_id == gateway_id,
                    OAuthToken.user_id == user_id
                )
            ).scalar_one_or_none()

            if not token_record:
                return None

            return {
                'user_id': token_record.user_id,
                'token_type': token_record.token_type,
                'expires_at': token_record.expires_at.isoformat() if token_record.expires_at else None,
                'scopes': token_record.scopes,
                'created_at': token_record.created_at.isoformat(),
                'updated_at': token_record.updated_at.isoformat(),
                'is_expired': self._is_token_expired(token_record, 0)
            }

        except Exception as e:
            logger.error(f"Failed to get token info: {str(e)}")
            return None

    async def revoke_user_tokens(
        self,
        gateway_id: str,
        user_id: str
    ) -> bool:
        """Revoke OAuth tokens for a specific user.

        Args:
            gateway_id: ID of the gateway
            user_id: OAuth provider user ID

        Returns:
            True if tokens were revoked successfully
        """
        try:
            token_record = self.db.execute(
                select(OAuthToken).where(
                    OAuthToken.gateway_id == gateway_id,
                    OAuthToken.user_id == user_id
                )
            ).scalar_one_or_none()

            if token_record:
                self.db.delete(token_record)
                self.db.commit()
                logger.info(f"Revoked OAuth tokens for gateway {gateway_id}, user {user_id}")
                return True

            return False

        except Exception as e:
            self.db.rollback()
            logger.error(f"Failed to revoke OAuth tokens: {str(e)}")
            return False

    async def cleanup_expired_tokens(self, max_age_days: int = 30) -> int:
        """Clean up expired OAuth tokens older than specified days.

        Args:
            max_age_days: Maximum age of tokens to keep

        Returns:
            Number of tokens cleaned up
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=max_age_days)

            expired_tokens = self.db.execute(
                select(OAuthToken).where(
                    OAuthToken.expires_at < cutoff_date
                )
            ).scalars().all()

            count = len(expired_tokens)
            for token in expired_tokens:
                self.db.delete(token)

            self.db.commit()
            logger.info(f"Cleaned up {count} expired OAuth tokens")
            return count

        except Exception as e:
            self.db.rollback()
            logger.error(f"Failed to cleanup expired tokens: {str(e)}")
            return 0
