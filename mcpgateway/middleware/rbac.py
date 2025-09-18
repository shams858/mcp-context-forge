# -*- coding: utf-8 -*-
"""RBAC Permission Checking Middleware.

This module provides middleware for FastAPI to enforce role-based access control
on API endpoints. It includes permission decorators and dependency injection
functions for protecting routes.
"""

# Standard
from functools import wraps
import logging
from typing import Callable, Generator, List, Optional

# Third-Party
from fastapi import Cookie, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.auth import get_current_user
from mcpgateway.db import SessionLocal
from mcpgateway.services.permission_service import PermissionService

logger = logging.getLogger(__name__)

# HTTP Bearer security scheme for token extraction
security = HTTPBearer(auto_error=False)


def get_db() -> Generator[Session, None, None]:
    """Get database session for dependency injection.

    Yields:
        Session: SQLAlchemy database session

    Examples:
        >>> gen = get_db()
        >>> db = next(gen)
        >>> hasattr(db, 'query')
        True
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def get_permission_service(db: Session = Depends(get_db)) -> PermissionService:
    """Get permission service instance for dependency injection.

    Args:
        db: Database session

    Returns:
        PermissionService: Permission checking service instance

    Examples:
        >>> import asyncio
        >>> asyncio.iscoroutinefunction(get_permission_service)
        True
    """
    return PermissionService(db)


async def get_current_user_with_permissions(
    request: Request, credentials: Optional[HTTPAuthorizationCredentials] = Depends(security), jwt_token: Optional[str] = Cookie(default=None), db: Session = Depends(get_db)
):
    """Extract current user from JWT token and prepare for permission checking.

    Args:
        request: FastAPI request object for IP/user-agent extraction
        credentials: HTTP Bearer credentials
        jwt_token: JWT token from cookie
        db: Database session

    Returns:
        dict: User information with permission checking context

    Raises:
        HTTPException: If authentication fails

    Examples:
        Use as FastAPI dependency::

            @app.get("/protected-endpoint")
            async def protected_route(user = Depends(get_current_user_with_permissions)):
                return {"user": user["email"]}
    """
    # Try multiple sources for the token, prioritizing manual cookie reading
    token = None

    # 1. First try manual cookie reading (most reliable)
    if request.cookies:
        # Try both jwt_token and access_token cookie names
        manual_token = request.cookies.get("jwt_token") or request.cookies.get("access_token")
        if manual_token:
            token = manual_token

    # 2. Then try Authorization header
    if not token and credentials and credentials.credentials:
        token = credentials.credentials

    # 3. Finally try FastAPI Cookie dependency (fallback)
    if not token and jwt_token:
        token = jwt_token

    if not token:
        # For browser requests (HTML Accept header or HTMX), redirect to login
        accept_header = request.headers.get("accept", "")
        is_htmx = request.headers.get("hx-request") == "true"
        if "text/html" in accept_header or is_htmx:
            raise HTTPException(status_code=status.HTTP_302_FOUND, detail="Authentication required", headers={"Location": "/admin/login"})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization token required")

    try:
        # Create credentials object if we got token from cookie
        if not credentials:
            credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

        # Extract user from token using the email auth function
        user = await get_current_user(credentials, db)

        # Add request context for permission auditing
        return {
            "email": user.email,
            "full_name": user.full_name,
            "is_admin": user.is_admin,
            "ip_address": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
            "db": db,
        }
    except Exception as e:
        logger.error(f"Authentication failed: {type(e).__name__}: {e}")

        # For browser requests (HTML Accept header or HTMX), redirect to login
        accept_header = request.headers.get("accept", "")
        is_htmx = request.headers.get("hx-request") == "true"
        if "text/html" in accept_header or is_htmx:
            raise HTTPException(status_code=status.HTTP_302_FOUND, detail="Authentication required", headers={"Location": "/admin/login"})

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication credentials")


def require_permission(permission: str, resource_type: Optional[str] = None):
    """Decorator to require specific permission for accessing an endpoint.

    Args:
        permission: Required permission (e.g., 'tools.create')
        resource_type: Optional resource type for resource-specific permissions

    Returns:
        Callable: Decorated function that enforces the permission requirement

    Examples:
        >>> decorator = require_permission("tools.create", "tools")
        >>> callable(decorator)
        True

        Execute wrapped function when permission granted:
        >>> import asyncio
        >>> class DummyPS:
        ...     def __init__(self, db):
        ...         pass
        ...     async def check_permission(self, **kwargs):
        ...         return True
        >>> @require_permission("tools.read")
        ... async def demo(user=None):
        ...     return "ok"
        >>> from unittest.mock import patch
        >>> with patch('mcpgateway.middleware.rbac.PermissionService', DummyPS):
        ...     asyncio.run(demo(user={"email": "u", "db": object()}))
        'ok'
    """

    def decorator(func: Callable) -> Callable:
        """Decorator function that wraps the original function with permission checking.

        Args:
            func: The function to be decorated

        Returns:
            Callable: The wrapped function with permission checking
        """

        @wraps(func)
        async def wrapper(*args, **kwargs):
            """Async wrapper function that performs permission check before calling original function.

            Args:
                *args: Positional arguments passed to the wrapped function
                **kwargs: Keyword arguments passed to the wrapped function

            Returns:
                Any: Result from the wrapped function if permission check passes

            Raises:
                HTTPException: If user authentication or permission check fails
            """
            # Extract user context from kwargs
            user_context = None
            for _, value in kwargs.items():
                if isinstance(value, dict) and "email" in value and "db" in value:
                    user_context = value
                    break

            if not user_context:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User authentication required")

            # Create permission service and check permission
            permission_service = PermissionService(user_context["db"])

            # Extract team_id from path parameters if available
            team_id = kwargs.get("team_id")

            # Check permission
            granted = await permission_service.check_permission(
                user_email=user_context["email"],
                permission=permission,
                resource_type=resource_type,
                team_id=team_id,
                ip_address=user_context.get("ip_address"),
                user_agent=user_context.get("user_agent"),
            )

            print(f"Permission check: user={user_context['email']}, permission={permission}, resource_type={resource_type}, granted={granted}")

            if not granted:
                logger.warning(f"Permission denied: user={user_context['email']}, permission={permission}, resource_type={resource_type}")
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Insufficient permissions. Required: {permission}")

            # Permission granted, execute the original function
            return await func(*args, **kwargs)

        return wrapper

    return decorator


def require_admin_permission():
    """Decorator to require admin permissions for accessing an endpoint.

    Returns:
        Callable: Decorated function that enforces admin permission requirement

    Examples:
        >>> decorator = require_admin_permission()
        >>> callable(decorator)
        True

        Execute when admin permission granted:
        >>> import asyncio
        >>> class DummyPS:
        ...     def __init__(self, db):
        ...         pass
        ...     async def check_admin_permission(self, email):
        ...         return True
        >>> @require_admin_permission()
        ... async def demo(user=None):
        ...     return "admin-ok"
        >>> from unittest.mock import patch
        >>> with patch('mcpgateway.middleware.rbac.PermissionService', DummyPS):
        ...     asyncio.run(demo(user={"email": "u", "db": object()}))
        'admin-ok'
    """

    def decorator(func: Callable) -> Callable:
        """Decorator function that wraps the original function with admin permission checking.

        Args:
            func: The function to be decorated

        Returns:
            Callable: The wrapped function with admin permission checking
        """

        @wraps(func)
        async def wrapper(*args, **kwargs):
            """Async wrapper function that performs admin permission check before calling original function.

            Args:
                *args: Positional arguments passed to the wrapped function
                **kwargs: Keyword arguments passed to the wrapped function

            Returns:
                Any: Result from the wrapped function if admin permission check passes

            Raises:
                HTTPException: If user authentication or admin permission check fails
            """
            # Extract user context from kwargs
            user_context = None
            for _, value in kwargs.items():
                if isinstance(value, dict) and "email" in value and "db" in value:
                    user_context = value
                    break

            if not user_context:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User authentication required")

            # Create permission service and check admin permissions
            permission_service = PermissionService(user_context["db"])

            has_admin_permission = await permission_service.check_admin_permission(user_context["email"])

            if not has_admin_permission:
                logger.warning(f"Admin permission denied: user={user_context['email']}")
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin permissions required")

            # Admin permission granted, execute the original function
            return await func(*args, **kwargs)

        return wrapper

    return decorator


def require_any_permission(permissions: List[str], resource_type: Optional[str] = None):
    """Decorator to require any of the specified permissions for accessing an endpoint.

    Args:
        permissions: List of permissions, user needs at least one
        resource_type: Optional resource type for resource-specific permissions

    Returns:
        Callable: Decorated function that enforces the permission requirements

    Examples:
        >>> decorator = require_any_permission(["tools.read", "tools.execute"], "tools")
        >>> callable(decorator)
        True

        Execute when any permission granted:
        >>> import asyncio
        >>> class DummyPS:
        ...     def __init__(self, db):
        ...         pass
        ...     async def check_permission(self, **kwargs):
        ...         return True
        >>> @require_any_permission(["tools.read", "tools.execute"], "tools")
        ... async def demo(user=None):
        ...     return "any-ok"
        >>> from unittest.mock import patch
        >>> with patch('mcpgateway.middleware.rbac.PermissionService', DummyPS):
        ...     asyncio.run(demo(user={"email": "u", "db": object()}))
        'any-ok'
    """

    def decorator(func: Callable) -> Callable:
        """Decorator function that wraps the original function with any-permission checking.

        Args:
            func: The function to be decorated

        Returns:
            Callable: The wrapped function with any-permission checking
        """

        @wraps(func)
        async def wrapper(*args, **kwargs):
            """Async wrapper function that performs any-permission check before calling original function.

            Args:
                *args: Positional arguments passed to the wrapped function
                **kwargs: Keyword arguments passed to the wrapped function

            Returns:
                Any: Result from the wrapped function if any-permission check passes

            Raises:
                HTTPException: If user authentication or any-permission check fails
            """
            # Extract user context from kwargs
            user_context = None
            for _, value in kwargs.items():
                if isinstance(value, dict) and "email" in value and "db" in value:
                    user_context = value
                    break

            if not user_context:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User authentication required")

            # Create permission service
            permission_service = PermissionService(user_context["db"])

            # Extract team_id from path parameters if available
            team_id = kwargs.get("team_id")

            # Check if user has any of the required permissions
            granted = False
            for permission in permissions:
                if await permission_service.check_permission(
                    user_email=user_context["email"],
                    permission=permission,
                    resource_type=resource_type,
                    team_id=team_id,
                    ip_address=user_context.get("ip_address"),
                    user_agent=user_context.get("user_agent"),
                ):
                    granted = True
                    break

            if not granted:
                logger.warning(f"Permission denied: user={user_context['email']}, permissions={permissions}, resource_type={resource_type}")
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Insufficient permissions. Required one of: {', '.join(permissions)}")

            # Permission granted, execute the original function
            return await func(*args, **kwargs)

        return wrapper

    return decorator


class PermissionChecker:
    """Context manager for manual permission checking.

    Useful for complex permission logic that can't be handled by decorators.

    Examples:
        >>> from unittest.mock import Mock
        >>> checker = PermissionChecker({"email": "user@example.com", "db": Mock()})
        >>> hasattr(checker, 'has_permission') and hasattr(checker, 'has_admin_permission')
        True
    """

    def __init__(self, user_context: dict):
        """Initialize permission checker with user context.

        Args:
            user_context: User context from get_current_user_with_permissions
        """
        self.user_context = user_context
        self.permission_service = PermissionService(user_context["db"])

    async def has_permission(self, permission: str, resource_type: Optional[str] = None, resource_id: Optional[str] = None, team_id: Optional[str] = None) -> bool:
        """Check if user has specific permission.

        Args:
            permission: Permission to check
            resource_type: Optional resource type
            resource_id: Optional resource ID
            team_id: Optional team context

        Returns:
            bool: True if user has permission
        """
        return await self.permission_service.check_permission(
            user_email=self.user_context["email"],
            permission=permission,
            resource_type=resource_type,
            resource_id=resource_id,
            team_id=team_id,
            ip_address=self.user_context.get("ip_address"),
            user_agent=self.user_context.get("user_agent"),
        )

    async def has_admin_permission(self) -> bool:
        """Check if user has admin permissions.

        Returns:
            bool: True if user has admin permissions
        """
        return await self.permission_service.check_admin_permission(self.user_context["email"])

    async def has_any_permission(self, permissions: List[str], resource_type: Optional[str] = None, team_id: Optional[str] = None) -> bool:
        """Check if user has any of the specified permissions.

        Args:
            permissions: List of permissions to check
            resource_type: Optional resource type
            team_id: Optional team context

        Returns:
            bool: True if user has at least one permission
        """
        for permission in permissions:
            if await self.has_permission(permission, resource_type, team_id=team_id):
                return True
        return False

    async def require_permission(self, permission: str, resource_type: Optional[str] = None, resource_id: Optional[str] = None, team_id: Optional[str] = None) -> None:
        """Require specific permission, raise HTTPException if not granted.

        Args:
            permission: Required permission
            resource_type: Optional resource type
            resource_id: Optional resource ID
            team_id: Optional team context

        Raises:
            HTTPException: If permission is not granted
        """
        if not await self.has_permission(permission, resource_type, resource_id, team_id):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Insufficient permissions. Required: {permission}")
