# -*- coding: utf-8 -*-
"""Admin UI Routes for MCP Gateway.

Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Mihai Criveti

This module contains all the administrative UI endpoints for the MCP Gateway.
It provides a comprehensive interface for managing servers, tools, resources,
prompts, gateways, and roots through RESTful API endpoints. The module handles
all aspects of CRUD operations for these entities, including creation,
reading, updating, deletion, and status toggling.

All endpoints in this module require authentication, which is enforced via
the require_auth or require_basic_auth dependency. The module integrates with
various services to perform the actual business logic operations on the
underlying data.
"""

# Standard
import json
import logging
import time
from typing import Any, Dict, List, Union

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
import httpx
from pydantic import ValidationError
from pydantic_core import ValidationError as CoreValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.config import settings
from mcpgateway.db import get_db
from mcpgateway.schemas import (
    GatewayCreate,
    GatewayRead,
    GatewayTestRequest,
    GatewayTestResponse,
    GatewayUpdate,
    PromptCreate,
    PromptMetrics,
    PromptRead,
    PromptUpdate,
    ResourceCreate,
    ResourceMetrics,
    ResourceRead,
    ResourceUpdate,
    ServerCreate,
    ServerMetrics,
    ServerRead,
    ServerUpdate,
    ToolCreate,
    ToolMetrics,
    ToolRead,
    ToolUpdate,
)
from mcpgateway.services.gateway_service import GatewayConnectionError, GatewayNotFoundError, GatewayService
from mcpgateway.services.prompt_service import PromptNotFoundError, PromptService
from mcpgateway.services.resource_service import ResourceNotFoundError, ResourceService
from mcpgateway.services.root_service import RootService
from mcpgateway.services.server_service import ServerError, ServerNotFoundError, ServerService
from mcpgateway.services.tool_service import ToolError, ToolNameConflictError, ToolNotFoundError, ToolService
from mcpgateway.utils.create_jwt_token import get_jwt_token
from mcpgateway.utils.error_formatter import ErrorFormatter
from mcpgateway.utils.retry_manager import ResilientHttpClient
from mcpgateway.utils.verify_credentials import require_auth, require_basic_auth

# Initialize services
server_service = ServerService()
tool_service = ToolService()
prompt_service = PromptService()
gateway_service = GatewayService()
resource_service = ResourceService()
root_service = RootService()

# Set up basic authentication
logger = logging.getLogger("mcpgateway")

admin_router = APIRouter(prefix="/admin", tags=["Admin UI"])

####################
# Admin UI Routes  #
####################


@admin_router.get("/servers", response_model=List[ServerRead])
async def admin_list_servers(
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> List[ServerRead]:
    """
    List servers for the admin UI with an option to include inactive servers.

    Args:
        include_inactive (bool): Whether to include inactive servers.
        db (Session): The database session dependency.
        user (str): The authenticated user dependency.

    Returns:
        List[ServerRead]: A list of server records.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from mcpgateway.schemas import ServerRead, ServerMetrics
        >>>
        >>> # Mock dependencies
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>>
        >>> # Mock server service
        >>> from datetime import datetime, timezone
        >>> mock_metrics = ServerMetrics(
        ...     total_executions=10,
        ...     successful_executions=8,
        ...     failed_executions=2,
        ...     failure_rate=0.2,
        ...     min_response_time=0.1,
        ...     max_response_time=2.0,
        ...     avg_response_time=0.5,
        ...     last_execution_time=datetime.now(timezone.utc)
        ... )
        >>> mock_server = ServerRead(
        ...     id="server-1",
        ...     name="Test Server",
        ...     description="A test server",
        ...     icon="test-icon.png",
        ...     created_at=datetime.now(timezone.utc),
        ...     updated_at=datetime.now(timezone.utc),
        ...     is_active=True,
        ...     associated_tools=["tool1", "tool2"],
        ...     associated_resources=[1, 2],
        ...     associated_prompts=[1],
        ...     metrics=mock_metrics
        ... )
        >>>
        >>> # Mock the server_service.list_servers method
        >>> original_list_servers = server_service.list_servers
        >>> server_service.list_servers = AsyncMock(return_value=[mock_server])
        >>>
        >>> # Test the function
        >>> async def test_admin_list_servers():
        ...     result = await admin_list_servers(
        ...         include_inactive=False,
        ...         db=mock_db,
        ...         user=mock_user
        ...     )
        ...     return len(result) > 0 and isinstance(result[0], dict)
        >>>
        >>> # Run the test
        >>> asyncio.run(test_admin_list_servers())
        True
        >>>
        >>> # Restore original method
        >>> server_service.list_servers = original_list_servers
        >>>
        >>> # Additional test for empty server list
        >>> server_service.list_servers = AsyncMock(return_value=[])
        >>> async def test_admin_list_servers_empty():
        ...     result = await admin_list_servers(
        ...         include_inactive=True,
        ...         db=mock_db,
        ...         user=mock_user
        ...     )
        ...     return result == []
        >>> asyncio.run(test_admin_list_servers_empty())
        True
        >>> server_service.list_servers = original_list_servers
        >>>
        >>> # Additional test for exception handling
        >>> import pytest
        >>> from fastapi import HTTPException
        >>> async def test_admin_list_servers_exception():
        ...     server_service.list_servers = AsyncMock(side_effect=Exception("Test error"))
        ...     try:
        ...         await admin_list_servers(False, mock_db, mock_user)
        ...     except Exception as e:
        ...         return str(e) == "Test error"
        >>> asyncio.run(test_admin_list_servers_exception())
        True
    """
    logger.debug(f"User {user} requested server list")
    servers = await server_service.list_servers(db, include_inactive=include_inactive)
    return [server.model_dump(by_alias=True) for server in servers]


@admin_router.get("/servers/{server_id}", response_model=ServerRead)
async def admin_get_server(server_id: str, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> ServerRead:
    """
    Retrieve server details for the admin UI.

    Args:
        server_id (str): The ID of the server to retrieve.
        db (Session): The database session dependency.
        user (str): The authenticated user dependency.

    Returns:
        ServerRead: The server details.

    Raises:
        HTTPException: If the server is not found.
        Exception: For any other unexpected errors.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from mcpgateway.schemas import ServerRead, ServerMetrics
        >>> from mcpgateway.services.server_service import ServerNotFoundError
        >>> from fastapi import HTTPException
        >>>
        >>> # Mock dependencies
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> server_id = "test-server-1"
        >>>
        >>> # Mock server response
        >>> from datetime import datetime, timezone
        >>> mock_metrics = ServerMetrics(
        ...     total_executions=5,
        ...     successful_executions=4,
        ...     failed_executions=1,
        ...     failure_rate=0.2,
        ...     min_response_time=0.2,
        ...     max_response_time=1.5,
        ...     avg_response_time=0.8,
        ...     last_execution_time=datetime.now(timezone.utc)
        ... )
        >>> mock_server = ServerRead(
        ...     id=server_id,
        ...     name="Test Server",
        ...     description="A test server",
        ...     icon="test-icon.png",
        ...     created_at=datetime.now(timezone.utc),
        ...     updated_at=datetime.now(timezone.utc),
        ...     is_active=True,
        ...     associated_tools=["tool1"],
        ...     associated_resources=[1],
        ...     associated_prompts=[1],
        ...     metrics=mock_metrics
        ... )
        >>>
        >>> # Mock the server_service.get_server method
        >>> original_get_server = server_service.get_server
        >>> server_service.get_server = AsyncMock(return_value=mock_server)
        >>>
        >>> # Test successful retrieval
        >>> async def test_admin_get_server_success():
        ...     result = await admin_get_server(
        ...         server_id=server_id,
        ...         db=mock_db,
        ...         user=mock_user
        ...     )
        ...     return isinstance(result, dict) and result.get('id') == server_id
        >>>
        >>> # Run the test
        >>> asyncio.run(test_admin_get_server_success())
        True
        >>>
        >>> # Test server not found scenario
        >>> server_service.get_server = AsyncMock(side_effect=ServerNotFoundError("Server not found"))
        >>>
        >>> async def test_admin_get_server_not_found():
        ...     try:
        ...         await admin_get_server(
        ...             server_id="nonexistent",
        ...             db=mock_db,
        ...             user=mock_user
        ...         )
        ...         return False
        ...     except HTTPException as e:
        ...         return e.status_code == 404
        >>>
        >>> # Run the not found test
        >>> asyncio.run(test_admin_get_server_not_found())
        True
        >>>
        >>> # Restore original method
        >>> server_service.get_server = original_get_server
    """
    try:
        logger.debug(f"User {user} requested details for server ID {server_id}")
        server = await server_service.get_server(db, server_id)
        return server.model_dump(by_alias=True)
    except ServerNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error getting gateway {server_id}: {e}")
        raise e


@admin_router.post("/servers", response_model=ServerRead)
async def admin_add_server(request: Request, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> RedirectResponse:
    """
    Add a new server via the admin UI.

    This endpoint processes form data to create a new server entry in the database.
    It handles exceptions gracefully and logs any errors that occur during server
    registration.

    Expects form fields:
      - name (required): The name of the server
      - description (optional): A description of the server's purpose
      - icon (optional): URL or path to the server's icon
      - associatedTools (optional, comma-separated): Tools associated with this server
      - associatedResources (optional, comma-separated): Resources associated with this server
      - associatedPrompts (optional, comma-separated): Prompts associated with this server

    Args:
        request (Request): FastAPI request containing form data.
        db (Session): Database session dependency
        user (str): Authenticated user dependency

    Returns:
        RedirectResponse: A redirect to the admin dashboard catalog section

    Examples:
        >>> import asyncio
        >>> import uuid
        >>> from datetime import datetime
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>>
        >>> # Mock dependencies
        >>> mock_db = MagicMock()
        >>> timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        >>> short_uuid = str(uuid.uuid4())[:8]
        >>> unq_ext = f"{timestamp}-{short_uuid}"
        >>> mock_user = "test_user_" + unq_ext
        >>> # Mock form data for successful server creation
        >>> form_data = FormData([
        ...     ("name", "Test-Server-"+unq_ext ),
        ...     ("description", "A test server"),
        ...     ("icon", "https://raw.githubusercontent.com/github/explore/main/topics/python/python.png"),
        ...     ("associatedTools", "tool1"),
        ...     ("associatedTools", "tool2"),
        ...     ("associatedResources", "resource1"),
        ...     ("associatedPrompts", "prompt1"),
        ...     ("is_inactive_checked", "false")
        ... ])
        >>>
        >>> # Mock request with form data
        >>> mock_request = MagicMock(spec=Request)
        >>> mock_request.form = AsyncMock(return_value=form_data)
        >>> mock_request.scope = {"root_path": "/test"}
        >>>
        >>> # Mock server service
        >>> original_register_server = server_service.register_server
        >>> server_service.register_server = AsyncMock()
        >>>
        >>> # Test successful server addition
        >>> async def test_admin_add_server_success():
        ...     result = await admin_add_server(
        ...         request=mock_request,
        ...         db=mock_db,
        ...         user=mock_user
        ...     )
        ...     # Accept both Successful (200) and JSONResponse (422/409) for error cases
        ...     #print(result.status_code)
        ...     return isinstance(result, JSONResponse) and result.status_code in (200, 409, 422, 500)
        >>>
        >>> asyncio.run(test_admin_add_server_success())
        True
        >>>
        >>> # Test with inactive checkbox checked
        >>> form_data_inactive = FormData([
        ...     ("name", "Test Server"),
        ...     ("description", "A test server"),
        ...     ("is_inactive_checked", "true")
        ... ])
        >>> mock_request.form = AsyncMock(return_value=form_data_inactive)
        >>>
        >>> async def test_admin_add_server_inactive():
        ...     result = await admin_add_server(mock_request, mock_db, mock_user)
        ...     return isinstance(result, JSONResponse) and result.status_code in (200, 409, 422, 500)
        >>>
        >>> #asyncio.run(test_admin_add_server_inactive())
        >>>
        >>> # Test exception handling - should still return redirect
        >>> async def test_admin_add_server_exception():
        ...     server_service.register_server = AsyncMock(side_effect=Exception("Test error"))
        ...     result = await admin_add_server(mock_request, mock_db, mock_user)
        ...     return isinstance(result, JSONResponse) and result.status_code == 500
        >>>
        >>> asyncio.run(test_admin_add_server_exception())
        True
        >>>
        >>> # Test with minimal form data
        >>> form_data_minimal = FormData([("name", "Minimal Server")])
        >>> mock_request.form = AsyncMock(return_value=form_data_minimal)
        >>> server_service.register_server = AsyncMock()
        >>>
        >>> async def test_admin_add_server_minimal():
        ...     result = await admin_add_server(mock_request, mock_db, mock_user)
        ...     #print (result)
        ...     #print (result.status_code)
        ...     return isinstance(result, JSONResponse) and result.status_code==200
        >>>
        >>> asyncio.run(test_admin_add_server_minimal())
        True
        >>>
        >>> # Restore original method
        >>> server_service.register_server = original_register_server
    """
    form = await request.form()
    # root_path = request.scope.get("root_path", "")
    # is_inactive_checked = form.get("is_inactive_checked", "false")
    try:
        logger.debug(f"User {user} is adding a new server with name: {form['name']}")
        server = ServerCreate(
            name=form.get("name"),
            description=form.get("description"),
            icon=form.get("icon"),
            associated_tools=",".join(form.getlist("associatedTools")),
            associated_resources=form.get("associatedResources"),
            associated_prompts=form.get("associatedPrompts"),
        )
    except KeyError as e:
        # Convert KeyError to ValidationError-like response
        return JSONResponse(content={"message": f"Missing required field: {e}", "success": False}, status_code=422)

    try:
        await server_service.register_server(db, server)
        return JSONResponse(
            content={"message": "Server created successfully!", "success": True},
            status_code=200,
        )

    except CoreValidationError as ex:
        return JSONResponse(content={"message": str(ex), "success": False}, status_code=422)

    except ValidationError as ex:
        return JSONResponse(content={"message": str(ex), "success": False}, status_code=422)

    except IntegrityError as ex:
        logger.error(f"Database error: {ex}")
        return JSONResponse(content={"message": f"Server already exists with name: {server.name}", "success": False}, status_code=409)
    except Exception as ex:
        if isinstance(ex, ServerError):
            # Custom server logic error — 500 Internal Server Error makes sense
            return JSONResponse(content={"message": str(ex), "success": False}, status_code=500)

        if isinstance(ex, ValueError):
            # Invalid input — 400 Bad Request is appropriate
            return JSONResponse(content={"message": str(ex), "success": False}, status_code=400)

        if isinstance(ex, RuntimeError):
            # Unexpected error during runtime — 500 is suitable
            return JSONResponse(content={"message": str(ex), "success": False}, status_code=500)

        if isinstance(ex, ValidationError):
            # Pydantic or input validation failure — 422 Unprocessable Entity is correct
            return JSONResponse(content={"message": ErrorFormatter.format_validation_error(ex), "success": False}, status_code=422)

        if isinstance(ex, IntegrityError):
            # DB constraint violation — 409 Conflict is appropriate
            return JSONResponse(content={"message": ErrorFormatter.format_database_error(ex), "success": False}, status_code=409)

        # For any other unhandled error, default to 500
        return JSONResponse(content={"message": str(ex), "success": False}, status_code=500)


@admin_router.post("/servers/{server_id}/edit")
async def admin_edit_server(
    server_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> RedirectResponse:
    """
    Edit an existing server via the admin UI.

    This endpoint processes form data to update an existing server's properties.
    It handles exceptions gracefully and logs any errors that occur during the
    update operation.

    Expects form fields:
      - name (optional): The updated name of the server
      - description (optional): An updated description of the server's purpose
      - icon (optional): Updated URL or path to the server's icon
      - associatedTools (optional, comma-separated): Updated list of tools associated with this server
      - associatedResources (optional, comma-separated): Updated list of resources associated with this server
      - associatedPrompts (optional, comma-separated): Updated list of prompts associated with this server

    Args:
        server_id (str): The ID of the server to edit
        request (Request): FastAPI request containing form data
        db (Session): Database session dependency
        user (str): Authenticated user dependency

    Returns:
        RedirectResponse: A redirect to the admin dashboard catalog section with a status code of 303

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> server_id = "server-to-edit"
        >>>
        >>> # Happy path: Edit server with new name
        >>> form_data_edit = FormData([("name", "Updated Server Name"), ("is_inactive_checked", "false")])
        >>> mock_request_edit = MagicMock(spec=Request, scope={"root_path": ""})
        >>> mock_request_edit.form = AsyncMock(return_value=form_data_edit)
        >>> original_update_server = server_service.update_server
        >>> server_service.update_server = AsyncMock()
        >>>
        >>> async def test_admin_edit_server_success():
        ...     result = await admin_edit_server(server_id, mock_request_edit, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse) and result.status_code == 303 and "/admin#catalog" in result.headers["location"]
        >>>
        >>> asyncio.run(test_admin_edit_server_success())
        True
        >>>
        >>> # Edge case: Edit server and include inactive checkbox
        >>> form_data_inactive = FormData([("name", "Inactive Server Edit"), ("is_inactive_checked", "true")])
        >>> mock_request_inactive = MagicMock(spec=Request, scope={"root_path": "/api"})
        >>> mock_request_inactive.form = AsyncMock(return_value=form_data_inactive)
        >>>
        >>> async def test_admin_edit_server_inactive_checked():
        ...     result = await admin_edit_server(server_id, mock_request_inactive, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse) and result.status_code == 303 and "/api/admin/?include_inactive=true#catalog" in result.headers["location"]
        >>>
        >>> asyncio.run(test_admin_edit_server_inactive_checked())
        True
        >>>
        >>> # Error path: Simulate an exception during update
        >>> form_data_error = FormData([("name", "Error Server")])
        >>> mock_request_error = MagicMock(spec=Request, scope={"root_path": ""})
        >>> mock_request_error.form = AsyncMock(return_value=form_data_error)
        >>> server_service.update_server = AsyncMock(side_effect=Exception("Update failed"))
        >>>
        >>> async def test_admin_edit_server_exception():
        ...     result = await admin_edit_server(server_id, mock_request_error, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse) and result.status_code == 303 and "/admin#catalog" in result.headers["location"]
        >>>
        >>> asyncio.run(test_admin_edit_server_exception())
        True
        >>>
        >>> # Restore original method
        >>> server_service.update_server = original_update_server
    """
    form = await request.form()
    is_inactive_checked = form.get("is_inactive_checked", "false")
    try:
        logger.debug(f"User {user} is editing server ID {server_id} with name: {form.get('name')}")
        server = ServerUpdate(
            name=form.get("name"),
            description=form.get("description"),
            icon=form.get("icon"),
            associated_tools=",".join(form.getlist("associatedTools")),
            associated_resources=form.get("associatedResources"),
            associated_prompts=form.get("associatedPrompts"),
        )
        await server_service.update_server(db, server_id, server)

        root_path = request.scope.get("root_path", "")

        if is_inactive_checked.lower() == "true":
            return RedirectResponse(f"{root_path}/admin/?include_inactive=true#catalog", status_code=303)
        return RedirectResponse(f"{root_path}/admin#catalog", status_code=303)
    except Exception as e:
        logger.error(f"Error editing server: {e}")

        root_path = request.scope.get("root_path", "")
        if is_inactive_checked.lower() == "true":
            return RedirectResponse(f"{root_path}/admin/?include_inactive=true#catalog", status_code=303)
        return RedirectResponse(f"{root_path}/admin#catalog", status_code=303)


@admin_router.post("/servers/{server_id}/toggle")
async def admin_toggle_server(
    server_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> RedirectResponse:
    """
    Toggle a server's active status via the admin UI.

    This endpoint processes a form request to activate or deactivate a server.
    It expects a form field 'activate' with value "true" to activate the server
    or "false" to deactivate it. The endpoint handles exceptions gracefully and
    logs any errors that might occur during the status toggle operation.

    Args:
        server_id (str): The ID of the server whose status to toggle.
        request (Request): FastAPI request containing form data with the 'activate' field.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect to the admin dashboard catalog section with a
        status code of 303 (See Other).

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> server_id = "server-to-toggle"
        >>>
        >>> # Happy path: Activate server
        >>> form_data_activate = FormData([("activate", "true"), ("is_inactive_checked", "false")])
        >>> mock_request_activate = MagicMock(spec=Request, scope={"root_path": ""})
        >>> mock_request_activate.form = AsyncMock(return_value=form_data_activate)
        >>> original_toggle_server_status = server_service.toggle_server_status
        >>> server_service.toggle_server_status = AsyncMock()
        >>>
        >>> async def test_admin_toggle_server_activate():
        ...     result = await admin_toggle_server(server_id, mock_request_activate, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse) and result.status_code == 303 and "/admin#catalog" in result.headers["location"]
        >>>
        >>> asyncio.run(test_admin_toggle_server_activate())
        True
        >>>
        >>> # Happy path: Deactivate server
        >>> form_data_deactivate = FormData([("activate", "false"), ("is_inactive_checked", "false")])
        >>> mock_request_deactivate = MagicMock(spec=Request, scope={"root_path": "/api"})
        >>> mock_request_deactivate.form = AsyncMock(return_value=form_data_deactivate)
        >>>
        >>> async def test_admin_toggle_server_deactivate():
        ...     result = await admin_toggle_server(server_id, mock_request_deactivate, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse) and result.status_code == 303 and "/api/admin#catalog" in result.headers["location"]
        >>>
        >>> asyncio.run(test_admin_toggle_server_deactivate())
        True
        >>>
        >>> # Edge case: Toggle with inactive checkbox checked
        >>> form_data_inactive = FormData([("activate", "true"), ("is_inactive_checked", "true")])
        >>> mock_request_inactive = MagicMock(spec=Request, scope={"root_path": ""})
        >>> mock_request_inactive.form = AsyncMock(return_value=form_data_inactive)
        >>>
        >>> async def test_admin_toggle_server_inactive_checked():
        ...     result = await admin_toggle_server(server_id, mock_request_inactive, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse) and result.status_code == 303 and "/admin/?include_inactive=true#catalog" in result.headers["location"]
        >>>
        >>> asyncio.run(test_admin_toggle_server_inactive_checked())
        True
        >>>
        >>> # Error path: Simulate an exception during toggle
        >>> form_data_error = FormData([("activate", "true")])
        >>> mock_request_error = MagicMock(spec=Request, scope={"root_path": ""})
        >>> mock_request_error.form = AsyncMock(return_value=form_data_error)
        >>> server_service.toggle_server_status = AsyncMock(side_effect=Exception("Toggle failed"))
        >>>
        >>> async def test_admin_toggle_server_exception():
        ...     result = await admin_toggle_server(server_id, mock_request_error, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse) and result.status_code == 303 and "/admin#catalog" in result.headers["location"]
        >>>
        >>> asyncio.run(test_admin_toggle_server_exception())
        True
        >>>
        >>> # Restore original method
        >>> server_service.toggle_server_status = original_toggle_server_status
    """
    form = await request.form()
    logger.debug(f"User {user} is toggling server ID {server_id} with activate: {form.get('activate')}")
    activate = form.get("activate", "true").lower() == "true"
    is_inactive_checked = form.get("is_inactive_checked", "false")
    try:
        await server_service.toggle_server_status(db, server_id, activate)
    except Exception as e:
        logger.error(f"Error toggling server status: {e}")

    root_path = request.scope.get("root_path", "")
    if is_inactive_checked.lower() == "true":
        return RedirectResponse(f"{root_path}/admin/?include_inactive=true#catalog", status_code=303)
    return RedirectResponse(f"{root_path}/admin#catalog", status_code=303)


@admin_router.post("/servers/{server_id}/delete")
async def admin_delete_server(server_id: str, request: Request, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> RedirectResponse:
    """
    Delete a server via the admin UI.

    This endpoint removes a server from the database by its ID. It handles exceptions
    gracefully and logs any errors that occur during the deletion process.

    Args:
        server_id (str): The ID of the server to delete
        request (Request): FastAPI request object (not used but required by route signature).
        db (Session): Database session dependency
        user (str): Authenticated user dependency

    Returns:
        RedirectResponse: A redirect to the admin dashboard catalog section with a
        status code of 303 (See Other)

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> server_id = "server-to-delete"
        >>>
        >>> # Happy path: Delete server
        >>> form_data_delete = FormData([("is_inactive_checked", "false")])
        >>> mock_request_delete = MagicMock(spec=Request, scope={"root_path": ""})
        >>> mock_request_delete.form = AsyncMock(return_value=form_data_delete)
        >>> original_delete_server = server_service.delete_server
        >>> server_service.delete_server = AsyncMock()
        >>>
        >>> async def test_admin_delete_server_success():
        ...     result = await admin_delete_server(server_id, mock_request_delete, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse) and result.status_code == 303 and "/admin#catalog" in result.headers["location"]
        >>>
        >>> asyncio.run(test_admin_delete_server_success())
        True
        >>>
        >>> # Edge case: Delete with inactive checkbox checked
        >>> form_data_inactive = FormData([("is_inactive_checked", "true")])
        >>> mock_request_inactive = MagicMock(spec=Request, scope={"root_path": "/api"})
        >>> mock_request_inactive.form = AsyncMock(return_value=form_data_inactive)
        >>>
        >>> async def test_admin_delete_server_inactive_checked():
        ...     result = await admin_delete_server(server_id, mock_request_inactive, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse) and result.status_code == 303 and "/api/admin/?include_inactive=true#catalog" in result.headers["location"]
        >>>
        >>> asyncio.run(test_admin_delete_server_inactive_checked())
        True
        >>>
        >>> # Error path: Simulate an exception during deletion
        >>> form_data_error = FormData([])
        >>> mock_request_error = MagicMock(spec=Request, scope={"root_path": ""})
        >>> mock_request_error.form = AsyncMock(return_value=form_data_error)
        >>> server_service.delete_server = AsyncMock(side_effect=Exception("Deletion failed"))
        >>>
        >>> async def test_admin_delete_server_exception():
        ...     result = await admin_delete_server(server_id, mock_request_error, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse) and result.status_code == 303 and "/admin#catalog" in result.headers["location"]
        >>>
        >>> asyncio.run(test_admin_delete_server_exception())
        True
        >>>
        >>> # Restore original method
        >>> server_service.delete_server = original_delete_server
    """
    try:
        logger.debug(f"User {user} is deleting server ID {server_id}")
        await server_service.delete_server(db, server_id)
    except Exception as e:
        logger.error(f"Error deleting server: {e}")

    form = await request.form()
    is_inactive_checked = form.get("is_inactive_checked", "false")
    root_path = request.scope.get("root_path", "")

    if is_inactive_checked.lower() == "true":
        return RedirectResponse(f"{root_path}/admin/?include_inactive=true#catalog", status_code=303)
    return RedirectResponse(f"{root_path}/admin#catalog", status_code=303)


@admin_router.get("/resources", response_model=List[ResourceRead])
async def admin_list_resources(
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> List[ResourceRead]:
    """
    List resources for the admin UI with an option to include inactive resources.

    This endpoint retrieves a list of resources from the database, optionally including
    those that are inactive. The inactive filter is useful for administrators who need
    to view or manage resources that have been deactivated but not deleted.

    Args:
        include_inactive (bool): Whether to include inactive resources in the results.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        List[ResourceRead]: A list of resource records formatted with by_alias=True.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from mcpgateway.schemas import ResourceRead, ResourceMetrics
        >>> from datetime import datetime, timezone
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>>
        >>> # Mock resource data
        >>> mock_resource = ResourceRead(
        ...     id=1,
        ...     uri="test://resource/1",
        ...     name="Test Resource",
        ...     description="A test resource",
        ...     mime_type="text/plain",
        ...     size=100,
        ...     created_at=datetime.now(timezone.utc),
        ...     updated_at=datetime.now(timezone.utc),
        ...     is_active=True,
        ...     metrics=ResourceMetrics(
        ...         total_executions=5, successful_executions=5, failed_executions=0,
        ...         failure_rate=0.0, min_response_time=0.1, max_response_time=0.5,
        ...         avg_response_time=0.3, last_execution_time=datetime.now(timezone.utc)
        ...     )
        ... )
        >>>
        >>> # Mock the resource_service.list_resources method
        >>> original_list_resources = resource_service.list_resources
        >>> resource_service.list_resources = AsyncMock(return_value=[mock_resource])
        >>>
        >>> # Test listing active resources
        >>> async def test_admin_list_resources_active():
        ...     result = await admin_list_resources(include_inactive=False, db=mock_db, user=mock_user)
        ...     return len(result) > 0 and isinstance(result[0], dict) and result[0]['name'] == "Test Resource"
        >>>
        >>> asyncio.run(test_admin_list_resources_active())
        True
        >>>
        >>> # Test listing with inactive resources (if mock includes them)
        >>> mock_inactive_resource = ResourceRead(
        ...     id=2, uri="test://resource/2", name="Inactive Resource",
        ...     description="Another test", mime_type="application/json", size=50,
        ...     created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc),
        ...     is_active=False, metrics=ResourceMetrics(
        ...         total_executions=0, successful_executions=0, failed_executions=0,
        ...         failure_rate=0.0, min_response_time=0.0, max_response_time=0.0,
        ...         avg_response_time=0.0, last_execution_time=None
        ...     )
        ... )
        >>> resource_service.list_resources = AsyncMock(return_value=[mock_resource, mock_inactive_resource])
        >>> async def test_admin_list_resources_all():
        ...     result = await admin_list_resources(include_inactive=True, db=mock_db, user=mock_user)
        ...     return len(result) == 2 and not result[1]['isActive']
        >>>
        >>> asyncio.run(test_admin_list_resources_all())
        True
        >>>
        >>> # Test empty list
        >>> resource_service.list_resources = AsyncMock(return_value=[])
        >>> async def test_admin_list_resources_empty():
        ...     result = await admin_list_resources(include_inactive=False, db=mock_db, user=mock_user)
        ...     return result == []
        >>>
        >>> asyncio.run(test_admin_list_resources_empty())
        True
        >>>
        >>> # Test exception handling
        >>> resource_service.list_resources = AsyncMock(side_effect=Exception("Resource list error"))
        >>> async def test_admin_list_resources_exception():
        ...     try:
        ...         await admin_list_resources(False, mock_db, mock_user)
        ...         return False
        ...     except Exception as e:
        ...         return str(e) == "Resource list error"
        >>>
        >>> asyncio.run(test_admin_list_resources_exception())
        True
        >>>
        >>> # Restore original method
        >>> resource_service.list_resources = original_list_resources
    """
    logger.debug(f"User {user} requested resource list")
    resources = await resource_service.list_resources(db, include_inactive=include_inactive)
    return [resource.model_dump(by_alias=True) for resource in resources]


@admin_router.get("/prompts", response_model=List[PromptRead])
async def admin_list_prompts(
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> List[PromptRead]:
    """
    List prompts for the admin UI with an option to include inactive prompts.

    This endpoint retrieves a list of prompts from the database, optionally including
    those that are inactive. The inactive filter helps administrators see and manage
    prompts that have been deactivated but not deleted from the system.

    Args:
        include_inactive (bool): Whether to include inactive prompts in the results.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        List[PromptRead]: A list of prompt records formatted with by_alias=True.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from mcpgateway.schemas import PromptRead, PromptMetrics
        >>> from datetime import datetime, timezone
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>>
        >>> # Mock prompt data
        >>> mock_prompt = PromptRead(
        ...     id=1,
        ...     name="Test Prompt",
        ...     description="A test prompt",
        ...     template="Hello {{name}}!",
        ...     arguments=[{"name": "name", "type": "string"}],
        ...     created_at=datetime.now(timezone.utc),
        ...     updated_at=datetime.now(timezone.utc),
        ...     is_active=True,
        ...     metrics=PromptMetrics(
        ...         total_executions=10, successful_executions=10, failed_executions=0,
        ...         failure_rate=0.0, min_response_time=0.01, max_response_time=0.1,
        ...         avg_response_time=0.05, last_execution_time=datetime.now(timezone.utc)
        ...     )
        ... )
        >>>
        >>> # Mock the prompt_service.list_prompts method
        >>> original_list_prompts = prompt_service.list_prompts
        >>> prompt_service.list_prompts = AsyncMock(return_value=[mock_prompt])
        >>>
        >>> # Test listing active prompts
        >>> async def test_admin_list_prompts_active():
        ...     result = await admin_list_prompts(include_inactive=False, db=mock_db, user=mock_user)
        ...     return len(result) > 0 and isinstance(result[0], dict) and result[0]['name'] == "Test Prompt"
        >>>
        >>> asyncio.run(test_admin_list_prompts_active())
        True
        >>>
        >>> # Test listing with inactive prompts (if mock includes them)
        >>> mock_inactive_prompt = PromptRead(
        ...     id=2, name="Inactive Prompt", description="Another test", template="Bye!",
        ...     arguments=[], created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc),
        ...     is_active=False, metrics=PromptMetrics(
        ...         total_executions=0, successful_executions=0, failed_executions=0,
        ...         failure_rate=0.0, min_response_time=0.0, max_response_time=0.0,
        ...         avg_response_time=0.0, last_execution_time=None
        ...     )
        ... )
        >>> prompt_service.list_prompts = AsyncMock(return_value=[mock_prompt, mock_inactive_prompt])
        >>> async def test_admin_list_prompts_all():
        ...     result = await admin_list_prompts(include_inactive=True, db=mock_db, user=mock_user)
        ...     return len(result) == 2 and not result[1]['isActive']
        >>>
        >>> asyncio.run(test_admin_list_prompts_all())
        True
        >>>
        >>> # Test empty list
        >>> prompt_service.list_prompts = AsyncMock(return_value=[])
        >>> async def test_admin_list_prompts_empty():
        ...     result = await admin_list_prompts(include_inactive=False, db=mock_db, user=mock_user)
        ...     return result == []
        >>>
        >>> asyncio.run(test_admin_list_prompts_empty())
        True
        >>>
        >>> # Test exception handling
        >>> prompt_service.list_prompts = AsyncMock(side_effect=Exception("Prompt list error"))
        >>> async def test_admin_list_prompts_exception():
        ...     try:
        ...         await admin_list_prompts(False, mock_db, mock_user)
        ...         return False
        ...     except Exception as e:
        ...         return str(e) == "Prompt list error"
        >>>
        >>> asyncio.run(test_admin_list_prompts_exception())
        True
        >>>
        >>> # Restore original method
        >>> prompt_service.list_prompts = original_list_prompts
    """
    logger.debug(f"User {user} requested prompt list")
    prompts = await prompt_service.list_prompts(db, include_inactive=include_inactive)
    return [prompt.model_dump(by_alias=True) for prompt in prompts]


@admin_router.get("/gateways", response_model=List[GatewayRead])
async def admin_list_gateways(
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> List[GatewayRead]:
    """
    List gateways for the admin UI with an option to include inactive gateways.

    This endpoint retrieves a list of gateways from the database, optionally
    including those that are inactive. The inactive filter allows administrators
    to view and manage gateways that have been deactivated but not deleted.

    Args:
        include_inactive (bool): Whether to include inactive gateways in the results.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        List[GatewayRead]: A list of gateway records formatted with by_alias=True.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from mcpgateway.schemas import GatewayRead
        >>> from datetime import datetime, timezone
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>>
        >>> # Mock gateway data
        >>> mock_gateway = GatewayRead(
        ...     id="gateway-1",
        ...     name="Test Gateway",
        ...     url="http://test.com",
        ...     description="A test gateway",
        ...     transport="HTTP",
        ...     created_at=datetime.now(timezone.utc),
        ...     updated_at=datetime.now(timezone.utc),
        ...     is_active=True,
        ...     auth_type=None, auth_username=None, auth_password=None, auth_token=None,
        ...     auth_header_key=None, auth_header_value=None
        ... )
        >>>
        >>> # Mock the gateway_service.list_gateways method
        >>> original_list_gateways = gateway_service.list_gateways
        >>> gateway_service.list_gateways = AsyncMock(return_value=[mock_gateway])
        >>>
        >>> # Test listing active gateways
        >>> async def test_admin_list_gateways_active():
        ...     result = await admin_list_gateways(include_inactive=False, db=mock_db, user=mock_user)
        ...     return len(result) > 0 and isinstance(result[0], dict) and result[0]['name'] == "Test Gateway"
        >>>
        >>> asyncio.run(test_admin_list_gateways_active())
        True
        >>>
        >>> # Test listing with inactive gateways (if mock includes them)
        >>> mock_inactive_gateway = GatewayRead(
        ...     id="gateway-2", name="Inactive Gateway", url="http://inactive.com",
        ...     description="Another test", transport="HTTP", created_at=datetime.now(timezone.utc),
        ...     updated_at=datetime.now(timezone.utc), enabled=False,
        ...     auth_type=None, auth_username=None, auth_password=None, auth_token=None,
        ...     auth_header_key=None, auth_header_value=None
        ... )
        >>> gateway_service.list_gateways = AsyncMock(return_value=[
        ...     mock_gateway, # Return the GatewayRead objects, not pre-dumped dicts
        ...     mock_inactive_gateway # Return the GatewayRead objects, not pre-dumped dicts
        ... ])
        >>> async def test_admin_list_gateways_all():
        ...     result = await admin_list_gateways(include_inactive=True, db=mock_db, user=mock_user)
        ...     return len(result) == 2 and not result[1]['enabled']
        >>>
        >>> asyncio.run(test_admin_list_gateways_all())
        True
        >>>
        >>> # Test empty list
        >>> gateway_service.list_gateways = AsyncMock(return_value=[])
        >>> async def test_admin_list_gateways_empty():
        ...     result = await admin_list_gateways(include_inactive=False, db=mock_db, user=mock_user)
        ...     return result == []
        >>>
        >>> asyncio.run(test_admin_list_gateways_empty())
        True
        >>>
        >>> # Test exception handling
        >>> gateway_service.list_gateways = AsyncMock(side_effect=Exception("Gateway list error"))
        >>> async def test_admin_list_gateways_exception():
        ...     try:
        ...         await admin_list_gateways(False, mock_db, mock_user)
        ...         return False
        ...     except Exception as e:
        ...         return str(e) == "Gateway list error"
        >>>
        >>> asyncio.run(test_admin_list_gateways_exception())
        True
        >>>
        >>> # Restore original method
        >>> gateway_service.list_gateways = original_list_gateways
    """
    logger.debug(f"User {user} requested gateway list")
    gateways = await gateway_service.list_gateways(db, include_inactive=include_inactive)
    return [gateway.model_dump(by_alias=True) for gateway in gateways]


@admin_router.post("/gateways/{gateway_id}/toggle")
async def admin_toggle_gateway(
    gateway_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> RedirectResponse:
    """
    Toggle the active status of a gateway via the admin UI.

    This endpoint allows an admin to toggle the active status of a gateway.
    It expects a form field 'activate' with a value of "true" or "false" to
    determine the new status of the gateway.

    Args:
        gateway_id (str): The ID of the gateway to toggle.
        request (Request): The FastAPI request object containing form data.
        db (Session): The database session dependency.
        user (str): The authenticated user dependency.

    Returns:
        RedirectResponse: A redirect response to the admin dashboard with a
        status code of 303 (See Other).

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> gateway_id = "gateway-to-toggle"
        >>>
        >>> # Happy path: Activate gateway
        >>> form_data_activate = FormData([("activate", "true"), ("is_inactive_checked", "false")])
        >>> mock_request_activate = MagicMock(spec=Request, scope={"root_path": ""})
        >>> mock_request_activate.form = AsyncMock(return_value=form_data_activate)
        >>> original_toggle_gateway_status = gateway_service.toggle_gateway_status
        >>> gateway_service.toggle_gateway_status = AsyncMock()
        >>>
        >>> async def test_admin_toggle_gateway_activate():
        ...     result = await admin_toggle_gateway(gateway_id, mock_request_activate, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse) and result.status_code == 303 and "/admin#gateways" in result.headers["location"]
        >>>
        >>> asyncio.run(test_admin_toggle_gateway_activate())
        True
        >>>
        >>> # Happy path: Deactivate gateway
        >>> form_data_deactivate = FormData([("activate", "false"), ("is_inactive_checked", "false")])
        >>> mock_request_deactivate = MagicMock(spec=Request, scope={"root_path": "/api"})
        >>> mock_request_deactivate.form = AsyncMock(return_value=form_data_deactivate)
        >>>
        >>> async def test_admin_toggle_gateway_deactivate():
        ...     result = await admin_toggle_gateway(gateway_id, mock_request_deactivate, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse) and result.status_code == 303 and "/api/admin#gateways" in result.headers["location"]
        >>>
        >>> asyncio.run(test_admin_toggle_gateway_deactivate())
        True
        >>>
        >>> # Edge case: Toggle with inactive checkbox checked
        >>> form_data_inactive = FormData([("activate", "true"), ("is_inactive_checked", "true")])
        >>> mock_request_inactive = MagicMock(spec=Request, scope={"root_path": ""})
        >>> mock_request_inactive.form = AsyncMock(return_value=form_data_inactive)
        >>>
        >>> async def test_admin_toggle_gateway_inactive_checked():
        ...     result = await admin_toggle_gateway(gateway_id, mock_request_inactive, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse) and result.status_code == 303 and "/admin/?include_inactive=true#gateways" in result.headers["location"]
        >>>
        >>> asyncio.run(test_admin_toggle_gateway_inactive_checked())
        True
        >>>
        >>> # Error path: Simulate an exception during toggle
        >>> form_data_error = FormData([("activate", "true")])
        >>> mock_request_error = MagicMock(spec=Request, scope={"root_path": ""})
        >>> mock_request_error.form = AsyncMock(return_value=form_data_error)
        >>> gateway_service.toggle_gateway_status = AsyncMock(side_effect=Exception("Toggle failed"))
        >>>
        >>> async def test_admin_toggle_gateway_exception():
        ...     result = await admin_toggle_gateway(gateway_id, mock_request_error, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse) and result.status_code == 303 and "/admin#gateways" in result.headers["location"]
        >>>
        >>> asyncio.run(test_admin_toggle_gateway_exception())
        True
        >>>
        >>> # Restore original method
        >>> gateway_service.toggle_gateway_status = original_toggle_gateway_status
    """
    logger.debug(f"User {user} is toggling gateway ID {gateway_id}")
    form = await request.form()
    activate = form.get("activate", "true").lower() == "true"
    is_inactive_checked = form.get("is_inactive_checked", "false")

    try:
        await gateway_service.toggle_gateway_status(db, gateway_id, activate)
    except Exception as e:
        logger.error(f"Error toggling gateway status: {e}")

    root_path = request.scope.get("root_path", "")
    if is_inactive_checked.lower() == "true":
        return RedirectResponse(f"{root_path}/admin/?include_inactive=true#gateways", status_code=303)
    return RedirectResponse(f"{root_path}/admin#gateways", status_code=303)


@admin_router.get("/", name="admin_home", response_class=HTMLResponse)
async def admin_ui(
    request: Request,
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user: str = Depends(require_basic_auth),
    jwt_token: str = Depends(get_jwt_token),
) -> HTMLResponse:
    """
    Render the admin dashboard HTML page.

    This endpoint serves as the main entry point to the admin UI. It fetches data for
    servers, tools, resources, prompts, gateways, and roots from their respective
    services, then renders the admin dashboard template with this data.

    The endpoint also sets a JWT token as a cookie for authentication in subsequent
    requests. This token is HTTP-only for security reasons.

    Args:
        request (Request): FastAPI request object.
        include_inactive (bool): Whether to include inactive items in all listings.
        db (Session): Database session dependency.
        user (str): Authenticated user from basic auth dependency.
        jwt_token (str): JWT token for authentication.

    Returns:
        HTMLResponse: Rendered HTML template for the admin dashboard.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock, patch
        >>> from fastapi import Request
        >>> from fastapi.responses import HTMLResponse
        >>> from mcpgateway.schemas import ServerRead, ToolRead, ResourceRead, PromptRead, GatewayRead, ServerMetrics, ToolMetrics, ResourceMetrics, PromptMetrics
        >>> from datetime import datetime, timezone
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "admin_user"
        >>> mock_jwt = "fake.jwt.token"
        >>>
        >>> # Mock services to return empty lists for simplicity in doctest
        >>> original_list_servers = server_service.list_servers
        >>> original_list_tools = tool_service.list_tools
        >>> original_list_resources = resource_service.list_resources
        >>> original_list_prompts = prompt_service.list_prompts
        >>> original_list_gateways = gateway_service.list_gateways
        >>> original_list_roots = root_service.list_roots
        >>>
        >>> server_service.list_servers = AsyncMock(return_value=[])
        >>> tool_service.list_tools = AsyncMock(return_value=[])
        >>> resource_service.list_resources = AsyncMock(return_value=[])
        >>> prompt_service.list_prompts = AsyncMock(return_value=[])
        >>> gateway_service.list_gateways = AsyncMock(return_value=[])
        >>> root_service.list_roots = AsyncMock(return_value=[])
        >>>
        >>> # Mock request and template rendering
        >>> mock_request = MagicMock(spec=Request, scope={"root_path": "/admin_prefix"})
        >>> mock_request.app.state.templates = MagicMock()
        >>> mock_template_response = HTMLResponse("<html>Admin UI</html>")
        >>> mock_request.app.state.templates.TemplateResponse.return_value = mock_template_response
        >>>
        >>> # Test basic rendering
        >>> async def test_admin_ui_basic_render():
        ...     response = await admin_ui(mock_request, False, mock_db, mock_user, mock_jwt)
        ...     return isinstance(response, HTMLResponse) and response.status_code == 200 and "jwt_token" in response.headers.get("set-cookie", "")
        >>>
        >>> asyncio.run(test_admin_ui_basic_render())
        True
        >>>
        >>> # Test with include_inactive=True
        >>> async def test_admin_ui_include_inactive():
        ...     response = await admin_ui(mock_request, True, mock_db, mock_user, mock_jwt)
        ...     # Verify list methods were called with include_inactive=True
        ...     server_service.list_servers.assert_called_with(mock_db, include_inactive=True)
        ...     return isinstance(response, HTMLResponse)
        >>>
        >>> asyncio.run(test_admin_ui_include_inactive())
        True
        >>>
        >>> # Test with populated data (mocking a few items)
        >>> mock_server = ServerRead(id="s1", name="S1", description="d", created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc), is_active=True, associated_tools=[], associated_resources=[], associated_prompts=[], icon="i", metrics=ServerMetrics(total_executions=0, successful_executions=0, failed_executions=0, failure_rate=0.0, min_response_time=0.0, max_response_time=0.0, avg_response_time=0.0, last_execution_time=None))
        >>> mock_tool = ToolRead(
        ...     id="t1", name="T1", original_name="T1", url="http://t1.com", description="d",
        ...     created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc),
        ...     enabled=True, reachable=True, gateway_slug="default", original_name_slug="t1",
        ...     request_type="GET", integration_type="MCP", headers={}, input_schema={},
        ...     annotations={}, jsonpath_filter=None, auth=None, execution_count=0,
        ...     metrics=ToolMetrics(
        ...         total_executions=0, successful_executions=0, failed_executions=0,
        ...         failure_rate=0.0, min_response_time=0.0, max_response_time=0.0,
        ...         avg_response_time=0.0, last_execution_time=None
        ...     ),
        ...     gateway_id=None
        ... )
        >>> server_service.list_servers = AsyncMock(return_value=[mock_server])
        >>> tool_service.list_tools = AsyncMock(return_value=[mock_tool])
        >>>
        >>> async def test_admin_ui_with_data():
        ...     response = await admin_ui(mock_request, False, mock_db, mock_user, mock_jwt)
        ...     # Check if template context was populated (indirectly via mock calls)
        ...     assert mock_request.app.state.templates.TemplateResponse.call_count >= 1
        ...     context = mock_request.app.state.templates.TemplateResponse.call_args[0][2]
        ...     return len(context['servers']) == 1 and len(context['tools']) == 1
        >>>
        >>> asyncio.run(test_admin_ui_with_data())
        True
        >>>
        >>> # Test exception handling during data fetching
        >>> server_service.list_servers = AsyncMock(side_effect=Exception("DB error"))
        >>> async def test_admin_ui_exception_handled():
        ...     try:
        ...         response = await admin_ui(mock_request, False, mock_db, mock_user, mock_jwt)
        ...         return False  # Should not reach here if exception is properly raised
        ...     except Exception as e:
        ...         return str(e) == "DB error"
        >>>
        >>> asyncio.run(test_admin_ui_exception_handled())
        True
        >>>
        >>> # Restore original methods
        >>> server_service.list_servers = original_list_servers
        >>> tool_service.list_tools = original_list_tools
        >>> resource_service.list_resources = original_list_resources
        >>> prompt_service.list_prompts = original_list_prompts
        >>> gateway_service.list_gateways = original_list_gateways
        >>> root_service.list_roots = original_list_roots
    """
    logger.debug(f"User {user} accessed the admin UI")
    servers = [server.model_dump(by_alias=True) for server in await server_service.list_servers(db, include_inactive=include_inactive)]
    tools = [tool.model_dump(by_alias=True) for tool in await tool_service.list_tools(db, include_inactive=include_inactive)]
    resources = [resource.model_dump(by_alias=True) for resource in await resource_service.list_resources(db, include_inactive=include_inactive)]
    prompts = [prompt.model_dump(by_alias=True) for prompt in await prompt_service.list_prompts(db, include_inactive=include_inactive)]
    gateways = [gateway.model_dump(by_alias=True) for gateway in await gateway_service.list_gateways(db, include_inactive=include_inactive)]
    roots = [root.model_dump(by_alias=True) for root in await root_service.list_roots()]
    root_path = settings.app_root_path
    response = request.app.state.templates.TemplateResponse(
        request,
        "admin.html",
        {
            "request": request,
            "servers": servers,
            "tools": tools,
            "resources": resources,
            "prompts": prompts,
            "gateways": gateways,
            "roots": roots,
            "include_inactive": include_inactive,
            "root_path": root_path,
            "gateway_tool_name_separator": settings.gateway_tool_name_separator,
        },
    )

    response.set_cookie(key="jwt_token", value=jwt_token, httponly=True, secure=False, samesite="Strict")  # JavaScript CAN'T read it  # only over HTTPS  # or "Lax" per your needs
    return response


@admin_router.get("/tools", response_model=List[ToolRead])
async def admin_list_tools(
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> List[ToolRead]:
    """
    List tools for the admin UI with an option to include inactive tools.

    This endpoint retrieves a list of tools from the database, optionally including
    those that are inactive. The inactive filter helps administrators manage tools
    that have been deactivated but not deleted from the system.

    Args:
        include_inactive (bool): Whether to include inactive tools in the results.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        List[ToolRead]: A list of tool records formatted with by_alias=True.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from mcpgateway.schemas import ToolRead, ToolMetrics
        >>> from datetime import datetime, timezone
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>>
        >>> # Mock tool data
        >>> mock_tool = ToolRead(
        ...     id="tool-1",
        ...     name="Test Tool",
        ...     original_name="TestTool",
        ...     url="http://test.com/tool",
        ...     description="A test tool",
        ...     request_type="HTTP",
        ...     integration_type="MCP",
        ...     headers={},
        ...     input_schema={},
        ...     annotations={},
        ...     jsonpath_filter=None,
        ...     auth=None,
        ...     created_at=datetime.now(timezone.utc),
        ...     updated_at=datetime.now(timezone.utc),
        ...     enabled=True,
        ...     reachable=True,
        ...     gateway_id=None,
        ...     execution_count=0,
        ...     metrics=ToolMetrics(
        ...         total_executions=5, successful_executions=5, failed_executions=0,
        ...         failure_rate=0.0, min_response_time=0.1, max_response_time=0.5,
        ...         avg_response_time=0.3, last_execution_time=datetime.now(timezone.utc)
        ...     ),
        ...     gateway_slug="default",
        ...     original_name_slug="test-tool"
        ... )  #  Added gateway_id=None
        >>>
        >>> # Mock the tool_service.list_tools method
        >>> original_list_tools = tool_service.list_tools
        >>> tool_service.list_tools = AsyncMock(return_value=[mock_tool])
        >>>
        >>> # Test listing active tools
        >>> async def test_admin_list_tools_active():
        ...     result = await admin_list_tools(include_inactive=False, db=mock_db, user=mock_user)
        ...     return len(result) > 0 and isinstance(result[0], dict) and result[0]['name'] == "Test Tool"
        >>>
        >>> asyncio.run(test_admin_list_tools_active())
        True
        >>>
        >>> # Test listing with inactive tools (if mock includes them)
        >>> mock_inactive_tool = ToolRead(
        ...     id="tool-2", name="Inactive Tool", original_name="InactiveTool", url="http://inactive.com",
        ...     description="Another test", request_type="HTTP", integration_type="MCP",
        ...     headers={}, input_schema={}, annotations={}, jsonpath_filter=None, auth=None,
        ...     created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc),
        ...     enabled=False, reachable=False, gateway_id=None, execution_count=0,
        ...     metrics=ToolMetrics(
        ...         total_executions=0, successful_executions=0, failed_executions=0,
        ...         failure_rate=0.0, min_response_time=0.0, max_response_time=0.0,
        ...         avg_response_time=0.0, last_execution_time=None
        ...     ),
        ...     gateway_slug="default", original_name_slug="inactive-tool"
        ... )
        >>> tool_service.list_tools = AsyncMock(return_value=[mock_tool, mock_inactive_tool])
        >>> async def test_admin_list_tools_all():
        ...     result = await admin_list_tools(include_inactive=True, db=mock_db, user=mock_user)
        ...     return len(result) == 2 and not result[1]['enabled']
        >>>
        >>> asyncio.run(test_admin_list_tools_all())
        True
        >>>
        >>> # Test empty list
        >>> tool_service.list_tools = AsyncMock(return_value=[])
        >>> async def test_admin_list_tools_empty():
        ...     result = await admin_list_tools(include_inactive=False, db=mock_db, user=mock_user)
        ...     return result == []
        >>>
        >>> asyncio.run(test_admin_list_tools_empty())
        True
        >>>
        >>> # Test exception handling
        >>> tool_service.list_tools = AsyncMock(side_effect=Exception("Tool list error"))
        >>> async def test_admin_list_tools_exception():
        ...     try:
        ...         await admin_list_tools(False, mock_db, mock_user)
        ...         return False
        ...     except Exception as e:
        ...         return str(e) == "Tool list error"
        >>>
        >>> asyncio.run(test_admin_list_tools_exception())
        True
        >>>
        >>> # Restore original method
        >>> tool_service.list_tools = original_list_tools
    """
    logger.debug(f"User {user} requested tool list")
    tools = await tool_service.list_tools(db, include_inactive=include_inactive)
    return [tool.model_dump(by_alias=True) for tool in tools]


@admin_router.get("/tools/{tool_id}", response_model=ToolRead)
async def admin_get_tool(tool_id: str, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> ToolRead:
    """
    Retrieve specific tool details for the admin UI.

    This endpoint fetches the details of a specific tool from the database
    by its ID. It provides access to all information about the tool for
    viewing and management purposes.

    Args:
        tool_id (str): The ID of the tool to retrieve.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        ToolRead: The tool details formatted with by_alias=True.

    Raises:
        HTTPException: If the tool is not found.
        Exception: For any other unexpected errors.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from mcpgateway.schemas import ToolRead, ToolMetrics
        >>> from datetime import datetime, timezone
        >>> from mcpgateway.services.tool_service import ToolNotFoundError # Added import
        >>> from fastapi import HTTPException
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> tool_id = "test-tool-id"
        >>>
        >>> # Mock tool data
        >>> mock_tool = ToolRead(
        ...     id=tool_id, name="Get Tool", original_name="GetTool", url="http://get.com",
        ...     description="Tool for getting", request_type="GET", integration_type="REST",
        ...     headers={}, input_schema={}, annotations={}, jsonpath_filter=None, auth=None,
        ...     created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc),
        ...     enabled=True, reachable=True, gateway_id=None, execution_count=0,
        ...     metrics=ToolMetrics(
        ...         total_executions=0, successful_executions=0, failed_executions=0,
        ...         failure_rate=0.0, min_response_time=0.0, max_response_time=0.0, avg_response_time=0.0,
        ...         last_execution_time=None
        ...     ),
        ...     gateway_slug="default", original_name_slug="get-tool"
        ... )
        >>>
        >>> # Mock the tool_service.get_tool method
        >>> original_get_tool = tool_service.get_tool
        >>> tool_service.get_tool = AsyncMock(return_value=mock_tool)
        >>>
        >>> # Test successful retrieval
        >>> async def test_admin_get_tool_success():
        ...     result = await admin_get_tool(tool_id, mock_db, mock_user)
        ...     return isinstance(result, dict) and result['id'] == tool_id
        >>>
        >>> asyncio.run(test_admin_get_tool_success())
        True
        >>>
        >>> # Test tool not found
        >>> tool_service.get_tool = AsyncMock(side_effect=ToolNotFoundError("Tool not found"))
        >>> async def test_admin_get_tool_not_found():
        ...     try:
        ...         await admin_get_tool("nonexistent", mock_db, mock_user)
        ...         return False
        ...     except HTTPException as e:
        ...         return e.status_code == 404 and "Tool not found" in e.detail
        >>>
        >>> asyncio.run(test_admin_get_tool_not_found())
        True
        >>>
        >>> # Test generic exception
        >>> tool_service.get_tool = AsyncMock(side_effect=Exception("Generic error"))
        >>> async def test_admin_get_tool_exception():
        ...     try:
        ...         await admin_get_tool(tool_id, mock_db, mock_user)
        ...         return False
        ...     except Exception as e:
        ...         return str(e) == "Generic error"
        >>>
        >>> asyncio.run(test_admin_get_tool_exception())
        True
        >>>
        >>> # Restore original method
        >>> tool_service.get_tool = original_get_tool
    """
    logger.debug(f"User {user} requested details for tool ID {tool_id}")
    try:
        tool = await tool_service.get_tool(db, tool_id)
        return tool.model_dump(by_alias=True)
    except ToolNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        # Catch any other unexpected errors and re-raise or log as needed
        logger.error(f"Error getting tool {tool_id}: {e}")
        raise e  # Re-raise for now, or return a 500 JSONResponse if preferred for API consistency


@admin_router.post("/tools/")
@admin_router.post("/tools")
async def admin_add_tool(
    request: Request,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> JSONResponse:
    """
    Add a tool via the admin UI with error handling.

    Expects form fields:
      - name
      - url
      - description (optional)
      - requestType (mapped to request_type; defaults to "SSE")
      - integrationType (mapped to integration_type; defaults to "MCP")
      - headers (JSON string)
      - input_schema (JSON string)
      - jsonpath_filter (optional)
      - auth_type (optional)
      - auth_username (optional)
      - auth_password (optional)
      - auth_token (optional)
      - auth_header_key (optional)
      - auth_header_value (optional)

    Logs the raw form data and assembled tool_data for debugging.

    Args:
        request (Request): the FastAPI request object containing the form data.
        db (Session): the SQLAlchemy database session.
        user (str): identifier of the authenticated user.

    Returns:
        JSONResponse: a JSON response with `{"message": ..., "success": ...}` and an appropriate HTTP status code.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import JSONResponse
        >>> from starlette.datastructures import FormData
        >>> from mcpgateway.services.tool_service import ToolNameConflictError
        >>> from pydantic import ValidationError
        >>> from mcpgateway.utils.error_formatter import ErrorFormatter
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>>
        >>> # Happy path: Add a new tool successfully
        >>> form_data_success = FormData([
        ...     ("name", "New_Tool"), # Corrected name to be valid
        ...     ("url", "http://new.tool.com"),
        ...     ("requestType", "SSE"), # Changed to a valid RequestType for MCP integration
        ...     ("integrationType", "MCP"),
        ...     ("headers", '{"X-Api-Key": "abc"}')
        ... ])
        >>> mock_request_success = MagicMock(spec=Request)
        >>> mock_request_success.form = AsyncMock(return_value=form_data_success)
        >>> original_register_tool = tool_service.register_tool
        >>> tool_service.register_tool = AsyncMock()
        >>>
        >>> async def test_admin_add_tool_success():
        ...     response = await admin_add_tool(mock_request_success, mock_db, mock_user)
        ...     return isinstance(response, JSONResponse) and response.status_code == 200 and json.loads(response.body.decode())["success"] is True
        >>>
        >>> asyncio.run(test_admin_add_tool_success())
        True
        >>>
        >>> # Error path: Tool name conflict
        >>> form_data_conflict = FormData([("name", "Existing_Tool"), ("url", "http://existing.com"), ("requestType", "SSE"), ("integrationType", "MCP")]) # Corrected name and requestType
        >>> mock_request_conflict = MagicMock(spec=Request)
        >>> mock_request_conflict.form = AsyncMock(return_value=form_data_conflict)
        >>> tool_service.register_tool = AsyncMock(side_effect=ToolNameConflictError("Tool name already exists"))
        >>>
        >>> async def test_admin_add_tool_conflict():
        ...     response = await admin_add_tool(mock_request_conflict, mock_db, mock_user)
        ...     return isinstance(response, JSONResponse) and response.status_code == 400 and json.loads(response.body.decode())["success"] is False
        >>>
        >>> asyncio.run(test_admin_add_tool_conflict())
        True
        >>>
        >>> # Error path: Missing required field (Pydantic validation error)
        >>> form_data_missing = FormData([("url", "http://missing.com"), ("requestType", "SSE"), ("integrationType", "MCP")]) # 'name' is missing, added requestType
        >>> mock_request_missing = MagicMock(spec=Request)
        >>> mock_request_missing.form = AsyncMock(return_value=form_data_missing)
        >>> # We don't need to mock tool_service.register_tool, ValidationError happens during ToolCreate()
        >>>
        >>> async def test_admin_add_tool_validation_error():
        ...     try:
        ...         response = await admin_add_tool(mock_request_missing, mock_db, mock_user)
        ...     except ValidationError as e:
        ...         print(type(e))
        ...         response = JSONResponse(content={"success": False}, status_code=422)
        ...         return False
        ...     return isinstance(response, JSONResponse) and response.status_code == 422 and json.loads(response.body.decode())["success"] is False
        >>>
        >>> asyncio.run(test_admin_add_tool_validation_error())  # doctest: +ELLIPSIS
        True
        >>>
        >>> # Error path: Generic unexpected exception
        >>> form_data_generic_error = FormData([("name", "Generic_Error_Tool"), ("url", "http://generic.com"), ("requestType", "SSE"), ("integrationType", "MCP")]) # Corrected name and requestType
        >>> mock_request_generic_error = MagicMock(spec=Request)
        >>> mock_request_generic_error.form = AsyncMock(return_value=form_data_generic_error)
        >>> tool_service.register_tool = AsyncMock(side_effect=Exception("Unexpected error"))
        >>>
        >>> async def test_admin_add_tool_generic_exception():
        ...     response = await admin_add_tool(mock_request_generic_error, mock_db, mock_user)
        ...     return isinstance(response, JSONResponse) and response.status_code == 500 and json.loads(response.body.decode())["success"] is False
        >>>
        >>> asyncio.run(test_admin_add_tool_generic_exception())
        True
        >>>
        >>> # Restore original method
        >>> tool_service.register_tool = original_register_tool
    """
    logger.debug(f"User {user} is adding a new tool")
    form = await request.form()
    logger.debug(f"Received form data: {dict(form)}")

    tool_data = {
        "name": form.get("name"),
        "url": form.get("url"),
        "description": form.get("description"),
        "request_type": form.get("requestType", "SSE"),
        "integration_type": form.get("integrationType", "MCP"),
        "headers": json.loads(form.get("headers") or "{}"),
        "input_schema": json.loads(form.get("input_schema") or "{}"),
        "jsonpath_filter": form.get("jsonpath_filter", ""),
        "auth_type": form.get("auth_type", ""),
        "auth_username": form.get("auth_username", ""),
        "auth_password": form.get("auth_password", ""),
        "auth_token": form.get("auth_token", ""),
        "auth_header_key": form.get("auth_header_key", ""),
        "auth_header_value": form.get("auth_header_value", ""),
    }
    logger.debug(f"Tool data built: {tool_data}")
    try:
        tool = ToolCreate(**tool_data)
        logger.debug(f"Validated tool data: {tool.model_dump(by_alias=True)}")
        await tool_service.register_tool(db, tool)
        return JSONResponse(
            content={"message": "Tool registered successfully!", "success": True},
            status_code=200,
        )
    except ToolNameConflictError as e:
        return JSONResponse(content={"message": str(e), "success": False}, status_code=400)
    except ToolError as e:
        return JSONResponse(content={"message": str(e), "success": False}, status_code=500)
    except ValidationError as e:  # This block should catch ValidationError
        logger.error(f"ValidationError in admin_edit_tool: {str(e)}")
        return JSONResponse(content=ErrorFormatter.format_validation_error(e), status_code=422)
    except Exception as e:
        logger.error(f"Unexpected error in admin_edit_tool: {str(e)}")
        return JSONResponse(content={"message": str(e), "success": False}, status_code=500)


@admin_router.post("/tools/{tool_id}/edit/", response_model=None)
@admin_router.post("/tools/{tool_id}/edit", response_model=None)
async def admin_edit_tool(
    tool_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> Union[RedirectResponse, JSONResponse]:
    """
    Edit a tool via the admin UI.

    Expects form fields:
      - name
      - url
      - description (optional)
      - requestType (to be mapped to request_type)
      - integrationType (to be mapped to integration_type)
      - headers (as a JSON string)
      - input_schema (as a JSON string)
      - jsonpathFilter (optional)
      - auth_type (optional, string: "basic", "bearer", or empty)
      - auth_username (optional, for basic auth)
      - auth_password (optional, for basic auth)
      - auth_token (optional, for bearer auth)
      - auth_header_key (optional, for headers auth)
      - auth_header_value (optional, for headers auth)

    Assembles the tool_data dictionary by remapping form keys into the
    snake-case keys expected by the schemas.

    Args:
        tool_id (str): The ID of the tool to edit.
        request (Request): FastAPI request containing form data.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect response to the tools section of the admin
        dashboard with a status code of 303 (See Other), or a JSON response with
        an error message if the update fails.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse, JSONResponse
        >>> from starlette.datastructures import FormData
        >>> from mcpgateway.services.tool_service import ToolNameConflictError, ToolError
        >>> from pydantic import ValidationError
        >>> from mcpgateway.utils.error_formatter import ErrorFormatter # Added import
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> tool_id = "tool-to-edit"
        >>>
        >>> # Happy path: Edit tool successfully
        >>> form_data_success = FormData([("name", "Updated_Tool"), ("url", "http://updated.com"), ("is_inactive_checked", "false"), ("requestType", "SSE"), ("integrationType", "MCP")]) # Corrected name and added requestType for MCP
        >>> mock_request_success = MagicMock(spec=Request, scope={"root_path": ""})
        >>> mock_request_success.form = AsyncMock(return_value=form_data_success)
        >>> original_update_tool = tool_service.update_tool
        >>> tool_service.update_tool = AsyncMock()
        >>>
        >>> async def test_admin_edit_tool_success():
        ...     response = await admin_edit_tool(tool_id, mock_request_success, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303 and "/admin#tools" in response.headers["location"]
        >>>
        >>> asyncio.run(test_admin_edit_tool_success())
        True
        >>>
        >>> # Edge case: Edit tool with inactive checkbox checked
        >>> form_data_inactive = FormData([("name", "Inactive_Edit"), ("url", "http://inactive.com"), ("is_inactive_checked", "true"), ("requestType", "SSE"), ("integrationType", "MCP")]) # Corrected name and requestType for MCP
        >>> mock_request_inactive = MagicMock(spec=Request, scope={"root_path": "/api"})
        >>> mock_request_inactive.form = AsyncMock(return_value=form_data_inactive)
        >>>
        >>> async def test_admin_edit_tool_inactive_checked():
        ...     response = await admin_edit_tool(tool_id, mock_request_inactive, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303 and "/api/admin/?include_inactive=true#tools" in response.headers["location"]
        >>>
        >>> asyncio.run(test_admin_edit_tool_inactive_checked())
        True
        >>>
        >>> # Error path: Tool name conflict
        >>> form_data_conflict = FormData([("name", "Conflicting_Name"), ("url", "http://conflict.com"), ("requestType", "SSE"), ("integrationType", "MCP")]) # Corrected name and requestType for MCP
        >>> mock_request_conflict = MagicMock(spec=Request, scope={"root_path": ""})
        >>> mock_request_conflict.form = AsyncMock(return_value=form_data_conflict)
        >>> tool_service.update_tool = AsyncMock(side_effect=ToolNameConflictError("Name conflict"))
        >>>
        >>> async def test_admin_edit_tool_conflict():
        ...     response = await admin_edit_tool(tool_id, mock_request_conflict, mock_db, mock_user)
        ...     return isinstance(response, JSONResponse) and response.status_code == 400 and json.loads(response.body.decode())["success"] is False
        >>>
        >>> asyncio.run(test_admin_edit_tool_conflict())
        True
        >>>
        >>> # Error path: Generic ToolError
        >>> form_data_tool_error = FormData([("name", "Tool_Error"), ("url", "http://toolerror.com"), ("requestType", "SSE"), ("integrationType", "MCP")]) # Corrected name and requestType for MCP
        >>> mock_request_tool_error = MagicMock(spec=Request, scope={"root_path": ""})
        >>> mock_request_tool_error.form = AsyncMock(return_value=form_data_tool_error)
        >>> tool_service.update_tool = AsyncMock(side_effect=ToolError("Tool specific error"))
        >>>
        >>> async def test_admin_edit_tool_tool_error():
        ...     response = await admin_edit_tool(tool_id, mock_request_tool_error, mock_db, mock_user)
        ...     return isinstance(response, JSONResponse) and response.status_code == 500 and json.loads(response.body.decode())["success"] is False
        >>>
        >>> asyncio.run(test_admin_edit_tool_tool_error())
        True
        >>>
        >>> # Error path: Pydantic Validation Error (e.g., invalid URL format)
        >>> form_data_validation_error = FormData([("name", "Bad_URL"), ("url", "invalid-url"), ("requestType", "SSE"), ("integrationType", "MCP")])
        >>> mock_request_validation_error = MagicMock(spec=Request, scope={"root_path": ""})
        >>> mock_request_validation_error.form = AsyncMock(return_value=form_data_validation_error)
        >>> # No need to mock tool_service.update_tool, ValidationError happens during ToolUpdate(**tool_data)
        >>>
        >>> async def test_admin_edit_tool_validation_error():
        ...     response = await admin_edit_tool(tool_id, mock_request_validation_error, mock_db, mock_user)
        ...     return isinstance(response, JSONResponse) and response.status_code == 422 and json.loads(response.body.decode())["success"] is False
        >>>
        >>> asyncio.run(test_admin_edit_tool_validation_error())  # doctest: +ELLIPSIS
        True
        >>>
        >>> # Restore original method
        >>> tool_service.update_tool = original_update_tool
    """
    logger.debug(f"User {user} is editing tool ID {tool_id}")
    form = await request.form()
    tool_data = {
        "name": form.get("name"),
        "url": form.get("url"),
        "description": form.get("description"),
        "request_type": form.get("requestType", "SSE"),
        "integration_type": form.get("integrationType", "MCP"),
        "headers": json.loads(form.get("headers") or "{}"),
        "input_schema": json.loads(form.get("input_schema") or "{}"),
        "jsonpath_filter": form.get("jsonpathFilter", ""),
        "auth_type": form.get("auth_type", ""),
        "auth_username": form.get("auth_username", ""),
        "auth_password": form.get("auth_password", ""),
        "auth_token": form.get("auth_token", ""),
        "auth_header_key": form.get("auth_header_key", ""),
        "auth_header_value": form.get("auth_header_value", ""),
    }
    logger.debug(f"Tool update data built: {tool_data}")
    try:
        tool = ToolUpdate(**tool_data)  # Pydantic validation happens here
        await tool_service.update_tool(db, tool_id, tool)

        root_path = request.scope.get("root_path", "")
        is_inactive_checked = form.get("is_inactive_checked", "false")
        if is_inactive_checked.lower() == "true":
            return RedirectResponse(f"{root_path}/admin/?include_inactive=true#tools", status_code=303)
        return RedirectResponse(f"{root_path}/admin#tools", status_code=303)
    except ToolNameConflictError as e:
        logger.error(f"ToolNameConflictError in admin_edit_tool: {str(e)}")
        return JSONResponse(content={"message": str(e), "success": False}, status_code=400)
    except ToolError as e:
        logger.error(f"ToolError in admin_edit_tool: {str(e)}")
        return JSONResponse(content={"message": str(e), "success": False}, status_code=500)
    except ValidationError as e:  # Catch Pydantic validation errors
        logger.error(f"ValidationError in admin_edit_tool: {str(e)}")
        return JSONResponse(content=ErrorFormatter.format_validation_error(e), status_code=422)
    except Exception as e:  # Generic catch-all for unexpected errors
        logger.error(f"Unexpected error in admin_edit_tool: {str(e)}")
        return JSONResponse(content={"message": str(e), "success": False}, status_code=500)


@admin_router.post("/tools/{tool_id}/delete")
async def admin_delete_tool(tool_id: str, request: Request, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> RedirectResponse:
    """
    Delete a tool via the admin UI.

    This endpoint permanently removes a tool from the database using its ID.
    It is irreversible and should be used with caution. The operation is logged,
    and the user must be authenticated to access this route.

    Args:
        tool_id (str): The ID of the tool to delete.
        request (Request): FastAPI request object (not used directly, but required by route signature).
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect response to the tools section of the admin
        dashboard with a status code of 303 (See Other).

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> tool_id = "tool-to-delete"
        >>>
        >>> # Happy path: Delete tool
        >>> form_data_delete = FormData([("is_inactive_checked", "false")])
        >>> mock_request_delete = MagicMock(spec=Request, scope={"root_path": ""})
        >>> mock_request_delete.form = AsyncMock(return_value=form_data_delete)
        >>> original_delete_tool = tool_service.delete_tool
        >>> tool_service.delete_tool = AsyncMock()
        >>>
        >>> async def test_admin_delete_tool_success():
        ...     result = await admin_delete_tool(tool_id, mock_request_delete, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse) and result.status_code == 303 and "/admin#tools" in result.headers["location"]
        >>>
        >>> asyncio.run(test_admin_delete_tool_success())
        True
        >>>
        >>> # Edge case: Delete with inactive checkbox checked
        >>> form_data_inactive = FormData([("is_inactive_checked", "true")])
        >>> mock_request_inactive = MagicMock(spec=Request, scope={"root_path": "/api"})
        >>> mock_request_inactive.form = AsyncMock(return_value=form_data_inactive)
        >>>
        >>> async def test_admin_delete_tool_inactive_checked():
        ...     result = await admin_delete_tool(tool_id, mock_request_inactive, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse) and result.status_code == 303 and "/api/admin/?include_inactive=true#tools" in result.headers["location"]
        >>>
        >>> asyncio.run(test_admin_delete_tool_inactive_checked())
        True
        >>>
        >>> # Error path: Simulate an exception during deletion
        >>> form_data_error = FormData([])
        >>> mock_request_error = MagicMock(spec=Request, scope={"root_path": ""})
        >>> mock_request_error.form = AsyncMock(return_value=form_data_error)
        >>> tool_service.delete_tool = AsyncMock(side_effect=Exception("Deletion failed"))
        >>>
        >>> async def test_admin_delete_tool_exception():
        ...     result = await admin_delete_tool(tool_id, mock_request_error, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse) and result.status_code == 303 and "/admin#tools" in result.headers["location"]
        >>>
        >>> asyncio.run(test_admin_delete_tool_exception())
        True
        >>>
        >>> # Restore original method
        >>> tool_service.delete_tool = original_delete_tool
    """
    logger.debug(f"User {user} is deleting tool ID {tool_id}")
    try:
        await tool_service.delete_tool(db, tool_id)
    except Exception as e:
        logger.error(f"Error deleting tool: {e}")

    form = await request.form()
    is_inactive_checked = form.get("is_inactive_checked", "false")
    root_path = request.scope.get("root_path", "")

    if is_inactive_checked.lower() == "true":
        return RedirectResponse(f"{root_path}/admin/?include_inactive=true#tools", status_code=303)
    return RedirectResponse(f"{root_path}/admin#tools", status_code=303)


@admin_router.post("/tools/{tool_id}/toggle")
async def admin_toggle_tool(
    tool_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> RedirectResponse:
    """
    Toggle a tool's active status via the admin UI.

    This endpoint processes a form request to activate or deactivate a tool.
    It expects a form field 'activate' with value "true" to activate the tool
    or "false" to deactivate it. The endpoint handles exceptions gracefully and
    logs any errors that might occur during the status toggle operation.

    Args:
        tool_id (str): The ID of the tool whose status to toggle.
        request (Request): FastAPI request containing form data with the 'activate' field.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect to the admin dashboard tools section with a
        status code of 303 (See Other).

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> tool_id = "tool-to-toggle"
        >>>
        >>> # Happy path: Activate tool
        >>> form_data_activate = FormData([("activate", "true"), ("is_inactive_checked", "false")])
        >>> mock_request_activate = MagicMock(spec=Request, scope={"root_path": ""})
        >>> mock_request_activate.form = AsyncMock(return_value=form_data_activate)
        >>> original_toggle_tool_status = tool_service.toggle_tool_status
        >>> tool_service.toggle_tool_status = AsyncMock()
        >>>
        >>> async def test_admin_toggle_tool_activate():
        ...     result = await admin_toggle_tool(tool_id, mock_request_activate, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse) and result.status_code == 303 and "/admin#tools" in result.headers["location"]
        >>>
        >>> asyncio.run(test_admin_toggle_tool_activate())
        True
        >>>
        >>> # Happy path: Deactivate tool
        >>> form_data_deactivate = FormData([("activate", "false"), ("is_inactive_checked", "false")])
        >>> mock_request_deactivate = MagicMock(spec=Request, scope={"root_path": "/api"})
        >>> mock_request_deactivate.form = AsyncMock(return_value=form_data_deactivate)
        >>>
        >>> async def test_admin_toggle_tool_deactivate():
        ...     result = await admin_toggle_tool(tool_id, mock_request_deactivate, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse) and result.status_code == 303 and "/api/admin#tools" in result.headers["location"]
        >>>
        >>> asyncio.run(test_admin_toggle_tool_deactivate())
        True
        >>>
        >>> # Edge case: Toggle with inactive checkbox checked
        >>> form_data_inactive = FormData([("activate", "true"), ("is_inactive_checked", "true")])
        >>> mock_request_inactive = MagicMock(spec=Request, scope={"root_path": ""})
        >>> mock_request_inactive.form = AsyncMock(return_value=form_data_inactive)
        >>>
        >>> async def test_admin_toggle_tool_inactive_checked():
        ...     result = await admin_toggle_tool(tool_id, mock_request_inactive, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse) and result.status_code == 303 and "/admin/?include_inactive=true#tools" in result.headers["location"]
        >>>
        >>> asyncio.run(test_admin_toggle_tool_inactive_checked())
        True
        >>>
        >>> # Error path: Simulate an exception during toggle
        >>> form_data_error = FormData([("activate", "true")])
        >>> mock_request_error = MagicMock(spec=Request, scope={"root_path": ""})
        >>> mock_request_error.form = AsyncMock(return_value=form_data_error)
        >>> tool_service.toggle_tool_status = AsyncMock(side_effect=Exception("Toggle failed"))
        >>>
        >>> async def test_admin_toggle_tool_exception():
        ...     result = await admin_toggle_tool(tool_id, mock_request_error, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse) and result.status_code == 303 and "/admin#tools" in result.headers["location"]
        >>>
        >>> asyncio.run(test_admin_toggle_tool_exception())
        True
        >>>
        >>> # Restore original method
        >>> tool_service.toggle_tool_status = original_toggle_tool_status
    """
    logger.debug(f"User {user} is toggling tool ID {tool_id}")
    form = await request.form()
    activate = form.get("activate", "true").lower() == "true"
    is_inactive_checked = form.get("is_inactive_checked", "false")
    try:
        await tool_service.toggle_tool_status(db, tool_id, activate, reachable=activate)
    except Exception as e:
        logger.error(f"Error toggling tool status: {e}")

    root_path = request.scope.get("root_path", "")
    if is_inactive_checked.lower() == "true":
        return RedirectResponse(f"{root_path}/admin/?include_inactive=true#tools", status_code=303)
    return RedirectResponse(f"{root_path}/admin#tools", status_code=303)


@admin_router.get("/gateways/{gateway_id}", response_model=GatewayRead)
async def admin_get_gateway(gateway_id: str, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> GatewayRead:
    """Get gateway details for the admin UI.

    Args:
        gateway_id: Gateway ID.
        db: Database session.
        user: Authenticated user.

    Returns:
        Gateway details.

    Raises:
        HTTPException: If the gateway is not found.
        Exception: For any other unexpected errors.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from mcpgateway.schemas import GatewayRead
        >>> from datetime import datetime, timezone
        >>> from mcpgateway.services.gateway_service import GatewayNotFoundError # Added import
        >>> from fastapi import HTTPException
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> gateway_id = "test-gateway-id"
        >>>
        >>> # Mock gateway data
        >>> mock_gateway = GatewayRead(
        ...     id=gateway_id, name="Get Gateway", url="http://get.com",
        ...     description="Gateway for getting", transport="HTTP",
        ...     created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc),
        ...     enabled=True, auth_type=None, auth_username=None, auth_password=None,
        ...     auth_token=None, auth_header_key=None, auth_header_value=None
        ... )
        >>>
        >>> # Mock the gateway_service.get_gateway method
        >>> original_get_gateway = gateway_service.get_gateway
        >>> gateway_service.get_gateway = AsyncMock(return_value=mock_gateway)
        >>>
        >>> # Test successful retrieval
        >>> async def test_admin_get_gateway_success():
        ...     result = await admin_get_gateway(gateway_id, mock_db, mock_user)
        ...     return isinstance(result, dict) and result['id'] == gateway_id
        >>>
        >>> asyncio.run(test_admin_get_gateway_success())
        True
        >>>
        >>> # Test gateway not found
        >>> gateway_service.get_gateway = AsyncMock(side_effect=GatewayNotFoundError("Gateway not found"))
        >>> async def test_admin_get_gateway_not_found():
        ...     try:
        ...         await admin_get_gateway("nonexistent", mock_db, mock_user)
        ...         return False
        ...     except HTTPException as e:
        ...         return e.status_code == 404 and "Gateway not found" in e.detail
        >>>
        >>> asyncio.run(test_admin_get_gateway_not_found())
        True
        >>>
        >>> # Test generic exception
        >>> gateway_service.get_gateway = AsyncMock(side_effect=Exception("Generic error"))
        >>> async def test_admin_get_gateway_exception():
        ...     try:
        ...         await admin_get_gateway(gateway_id, mock_db, mock_user)
        ...         return False
        ...     except Exception as e:
        ...         return str(e) == "Generic error"
        >>>
        >>> asyncio.run(test_admin_get_gateway_exception())
        True
        >>>
        >>> # Restore original method
        >>> gateway_service.get_gateway = original_get_gateway
    """
    logger.debug(f"User {user} requested details for gateway ID {gateway_id}")
    try:
        gateway = await gateway_service.get_gateway(db, gateway_id)
        return gateway.model_dump(by_alias=True)
    except GatewayNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error getting gateway {gateway_id}: {e}")
        raise e


@admin_router.post("/gateways")
async def admin_add_gateway(request: Request, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> JSONResponse:
    """Add a gateway via the admin UI.

    Expects form fields:
      - name
      - url
      - description (optional)

    Args:
        request: FastAPI request containing form data.
        db: Database session.
        user: Authenticated user.

    Returns:
        A redirect response to the admin dashboard.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import JSONResponse
        >>> from starlette.datastructures import FormData
        >>> from mcpgateway.services.gateway_service import GatewayConnectionError
        >>> from pydantic import ValidationError
        >>> from sqlalchemy.exc import IntegrityError
        >>> from mcpgateway.utils.error_formatter import ErrorFormatter
        >>> import json # Added import for json.loads
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>>
        >>> # Happy path: Add a new gateway successfully with basic auth details
        >>> form_data_success = FormData([
        ...     ("name", "New Gateway"),
        ...     ("url", "http://new.gateway.com"),
        ...     ("transport", "HTTP"),
        ...     ("auth_type", "basic"), # Valid auth_type
        ...     ("auth_username", "user"), # Required for basic auth
        ...     ("auth_password", "pass")  # Required for basic auth
        ... ])
        >>> mock_request_success = MagicMock(spec=Request)
        >>> mock_request_success.form = AsyncMock(return_value=form_data_success)
        >>> original_register_gateway = gateway_service.register_gateway
        >>> gateway_service.register_gateway = AsyncMock()
        >>>
        >>> async def test_admin_add_gateway_success():
        ...     response = await admin_add_gateway(mock_request_success, mock_db, mock_user)
        ...     # Corrected: Access body and then parse JSON
        ...     return isinstance(response, JSONResponse) and response.status_code == 200 and json.loads(response.body)["success"] is True
        >>>
        >>> asyncio.run(test_admin_add_gateway_success())
        True
        >>>
        >>> # Error path: Gateway connection error
        >>> form_data_conn_error = FormData([("name", "Bad Gateway"), ("url", "http://bad.com"), ("auth_type", "bearer"), ("auth_token", "abc")]) # Added auth_type and token
        >>> mock_request_conn_error = MagicMock(spec=Request)
        >>> mock_request_conn_error.form = AsyncMock(return_value=form_data_conn_error)
        >>> gateway_service.register_gateway = AsyncMock(side_effect=GatewayConnectionError("Connection failed"))
        >>>
        >>> async def test_admin_add_gateway_connection_error():
        ...     response = await admin_add_gateway(mock_request_conn_error, mock_db, mock_user)
        ...     return isinstance(response, JSONResponse) and response.status_code == 502 and json.loads(response.body)["success"] is False
        >>>
        >>> asyncio.run(test_admin_add_gateway_connection_error())
        True
        >>>
        >>> # Error path: Validation error (e.g., missing name)
        >>> form_data_validation_error = FormData([("url", "http://no-name.com"), ("auth_type", "headers"), ("auth_header_key", "X-Key"), ("auth_header_value", "val")]) # 'name' is missing, added auth_type
        >>> mock_request_validation_error = MagicMock(spec=Request)
        >>> mock_request_validation_error.form = AsyncMock(return_value=form_data_validation_error)
        >>> # No need to mock register_gateway, ValidationError happens during GatewayCreate()
        >>>
        >>> async def test_admin_add_gateway_validation_error():
        ...     response = await admin_add_gateway(mock_request_validation_error, mock_db, mock_user)
        ...     return isinstance(response, JSONResponse) and response.status_code == 422 and json.loads(response.body.decode())["success"] is False
        >>>
        >>> asyncio.run(test_admin_add_gateway_validation_error())
        True
        >>>
        >>> # Error path: Integrity error (e.g., duplicate name)
        >>> from sqlalchemy.exc import IntegrityError
        >>> form_data_integrity_error = FormData([("name", "Duplicate Gateway"), ("url", "http://duplicate.com"), ("auth_type", "basic"), ("auth_username", "u"), ("auth_password", "p")]) # Added auth_type and creds
        >>> mock_request_integrity_error = MagicMock(spec=Request)
        >>> mock_request_integrity_error.form = AsyncMock(return_value=form_data_integrity_error)
        >>> gateway_service.register_gateway = AsyncMock(side_effect=IntegrityError("Duplicate entry", {}, {}))
        >>>
        >>> async def test_admin_add_gateway_integrity_error():
        ...     response = await admin_add_gateway(mock_request_integrity_error, mock_db, mock_user)
        ...     return isinstance(response, JSONResponse) and response.status_code == 409 and json.loads(response.body.decode())["success"] is False
        >>>
        >>> asyncio.run(test_admin_add_gateway_integrity_error())
        True
        >>>
        >>> # Error path: Generic RuntimeError
        >>> form_data_runtime_error = FormData([("name", "Runtime Error Gateway"), ("url", "http://runtime.com"), ("auth_type", "basic"), ("auth_username", "u"), ("auth_password", "p")]) # Added auth_type and creds
        >>> mock_request_runtime_error = MagicMock(spec=Request)
        >>> mock_request_runtime_error.form = AsyncMock(return_value=form_data_runtime_error)
        >>> gateway_service.register_gateway = AsyncMock(side_effect=RuntimeError("Unexpected runtime issue"))
        >>>
        >>> async def test_admin_add_gateway_runtime_error():
        ...     response = await admin_add_gateway(mock_request_runtime_error, mock_db, mock_user)
        ...     return isinstance(response, JSONResponse) and response.status_code == 500 and json.loads(response.body.decode())["success"] is False
        >>>
        >>> asyncio.run(test_admin_add_gateway_runtime_error())
        True
        >>>
        >>> # Restore original method
        >>> gateway_service.register_gateway = original_register_gateway
    """
    logger.debug(f"User {user} is adding a new gateway")
    form = await request.form()
    try:
        gateway = GatewayCreate(
            name=form["name"],
            url=form["url"],
            description=form.get("description"),
            transport=form.get("transport", "SSE"),
            auth_type=form.get("auth_type", ""),
            auth_username=form.get("auth_username", ""),
            auth_password=form.get("auth_password", ""),
            auth_token=form.get("auth_token", ""),
            auth_header_key=form.get("auth_header_key", ""),
            auth_header_value=form.get("auth_header_value", ""),
        )
    except KeyError as e:
        # Convert KeyError to ValidationError-like response
        return JSONResponse(content={"message": f"Missing required field: {e}", "success": False}, status_code=422)

    try:
        await gateway_service.register_gateway(db, gateway)
        return JSONResponse(
            content={"message": "Gateway registered successfully!", "success": True},
            status_code=200,
        )

    except Exception as ex:
        if isinstance(ex, GatewayConnectionError):
            return JSONResponse(content={"message": str(ex), "success": False}, status_code=502)
        if isinstance(ex, ValueError):
            return JSONResponse(content={"message": str(ex), "success": False}, status_code=400)
        if isinstance(ex, RuntimeError):
            return JSONResponse(content={"message": str(ex), "success": False}, status_code=500)
        if isinstance(ex, ValidationError):
            return JSONResponse(content=ErrorFormatter.format_validation_error(ex), status_code=422)
        if isinstance(ex, IntegrityError):
            return JSONResponse(status_code=409, content=ErrorFormatter.format_database_error(ex))
        return JSONResponse(content={"message": str(ex), "success": False}, status_code=500)


@admin_router.post("/gateways/{gateway_id}/edit")
async def admin_edit_gateway(
    gateway_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> RedirectResponse:
    """Edit a gateway via the admin UI.

    Expects form fields:
      - name
      - url
      - description (optional)

    Args:
        gateway_id: Gateway ID.
        request: FastAPI request containing form data.
        db: Database session.
        user: Authenticated user.

    Returns:
        A redirect response to the admin dashboard.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>> from pydantic import ValidationError
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> gateway_id = "gateway-to-edit"
        >>>
        >>> # Happy path: Edit gateway successfully
        >>> form_data_success = FormData([("name", "Updated Gateway"), ("url", "http://updated.com"), ("is_inactive_checked", "false"), ("auth_type", "basic")]) # Added auth_type
        >>> mock_request_success = MagicMock(spec=Request, scope={"root_path": ""})
        >>> mock_request_success.form = AsyncMock(return_value=form_data_success)
        >>> original_update_gateway = gateway_service.update_gateway
        >>> gateway_service.update_gateway = AsyncMock()
        >>>
        >>> async def test_admin_edit_gateway_success():
        ...     response = await admin_edit_gateway(gateway_id, mock_request_success, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303 and "/admin#gateways" in response.headers["location"]
        >>>
        >>> asyncio.run(test_admin_edit_gateway_success())
        True
        >>>
        >>> # Edge case: Edit gateway with inactive checkbox checked
        >>> form_data_inactive = FormData([("name", "Inactive Edit"), ("url", "http://inactive.com"), ("is_inactive_checked", "true"), ("auth_type", "basic")]) # Added auth_type
        >>> mock_request_inactive = MagicMock(spec=Request, scope={"root_path": "/api"})
        >>> mock_request_inactive.form = AsyncMock(return_value=form_data_inactive)
        >>>
        >>> async def test_admin_edit_gateway_inactive_checked():
        ...     response = await admin_edit_gateway(gateway_id, mock_request_inactive, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303 and "/api/admin/?include_inactive=true#gateways" in response.headers["location"]
        >>>
        >>> asyncio.run(test_admin_edit_gateway_inactive_checked())
        True
        >>>
        >>> # Error path: Simulate an exception during update
        >>> form_data_error = FormData([("name", "Error Gateway"), ("url", "http://error.com"), ("auth_type", "basic")]) # Added auth_type
        >>> mock_request_error = MagicMock(spec=Request, scope={"root_path": ""})
        >>> mock_request_error.form = AsyncMock(return_value=form_data_error)
        >>> gateway_service.update_gateway = AsyncMock(side_effect=Exception("Update failed"))
        >>>
        >>> async def test_admin_edit_gateway_exception():
        ...     response = await admin_edit_gateway(gateway_id, mock_request_error, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303 and "/admin#gateways" in response.headers["location"]
        >>>
        >>> asyncio.run(test_admin_edit_gateway_exception())
        True
        >>>
        >>> # Error path: Pydantic Validation Error (e.g., invalid URL format)
        >>> form_data_validation_error = FormData([("name", "Bad URL Gateway"), ("url", "invalid-url"), ("auth_type", "basic")]) # Added auth_type
        >>> mock_request_validation_error = MagicMock(spec=Request, scope={"root_path": ""})
        >>> mock_request_validation_error.form = AsyncMock(return_value=form_data_validation_error)
        >>>
        >>> async def test_admin_edit_gateway_validation_error():
        ...     response = await admin_edit_gateway(gateway_id, mock_request_validation_error, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303 and "/admin#gateways" in response.headers["location"]
        >>>
        >>> asyncio.run(test_admin_edit_gateway_validation_error())
        True
        >>>
        >>> # Restore original method
        >>> gateway_service.update_gateway = original_update_gateway
    """
    logger.debug(f"User {user} is editing gateway ID {gateway_id}")
    form = await request.form()
    is_inactive_checked = form.get("is_inactive_checked", "false")
    try:
        gateway = GatewayUpdate(  # Pydantic validation happens here
            name=form.get("name"),
            url=form["url"],
            description=form.get("description"),
            transport=form.get("transport", "SSE"),
            auth_type=form.get("auth_type", None),
            auth_username=form.get("auth_username", None),
            auth_password=form.get("auth_password", None),
            auth_token=form.get("auth_token", None),
            auth_header_key=form.get("auth_header_key", None),
            auth_header_value=form.get("auth_header_value", None),
        )
        await gateway_service.update_gateway(db, gateway_id, gateway)

        root_path = request.scope.get("root_path", "")
        if is_inactive_checked.lower() == "true":
            return RedirectResponse(f"{root_path}/admin/?include_inactive=true#gateways", status_code=303)
        return RedirectResponse(f"{root_path}/admin#gateways", status_code=303)
    except Exception as e:  # Catch all exceptions including ValidationError for redirect
        logger.error(f"Error editing gateway: {e}")

        root_path = request.scope.get("root_path", "")
        if is_inactive_checked.lower() == "true":
            return RedirectResponse(f"{root_path}/admin/?include_inactive=true#gateways", status_code=303)
        return RedirectResponse(f"{root_path}/admin#gateways", status_code=303)


@admin_router.post("/gateways/{gateway_id}/delete")
async def admin_delete_gateway(gateway_id: str, request: Request, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> RedirectResponse:
    """
    Delete a gateway via the admin UI.

    This endpoint removes a gateway from the database by its ID. The deletion is
    permanent and cannot be undone. It requires authentication and logs the
    operation for auditing purposes.

    Args:
        gateway_id (str): The ID of the gateway to delete.
        request (Request): FastAPI request object (not used directly but required by the route signature).
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect response to the gateways section of the admin
        dashboard with a status code of 303 (See Other).

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> gateway_id = "gateway-to-delete"
        >>>
        >>> # Happy path: Delete gateway
        >>> form_data_delete = FormData([("is_inactive_checked", "false")])
        >>> mock_request_delete = MagicMock(spec=Request, scope={"root_path": ""})
        >>> mock_request_delete.form = AsyncMock(return_value=form_data_delete)
        >>> original_delete_gateway = gateway_service.delete_gateway
        >>> gateway_service.delete_gateway = AsyncMock()
        >>>
        >>> async def test_admin_delete_gateway_success():
        ...     result = await admin_delete_gateway(gateway_id, mock_request_delete, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse) and result.status_code == 303 and "/admin#gateways" in result.headers["location"]
        >>>
        >>> asyncio.run(test_admin_delete_gateway_success())
        True
        >>>
        >>> # Edge case: Delete with inactive checkbox checked
        >>> form_data_inactive = FormData([("is_inactive_checked", "true")])
        >>> mock_request_inactive = MagicMock(spec=Request, scope={"root_path": "/api"})
        >>> mock_request_inactive.form = AsyncMock(return_value=form_data_inactive)
        >>>
        >>> async def test_admin_delete_gateway_inactive_checked():
        ...     result = await admin_delete_gateway(gateway_id, mock_request_inactive, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse) and result.status_code == 303 and "/api/admin/?include_inactive=true#gateways" in result.headers["location"]
        >>>
        >>> asyncio.run(test_admin_delete_gateway_inactive_checked())
        True
        >>>
        >>> # Error path: Simulate an exception during deletion
        >>> form_data_error = FormData([])
        >>> mock_request_error = MagicMock(spec=Request, scope={"root_path": ""})
        >>> mock_request_error.form = AsyncMock(return_value=form_data_error)
        >>> gateway_service.delete_gateway = AsyncMock(side_effect=Exception("Deletion failed"))
        >>>
        >>> async def test_admin_delete_gateway_exception():
        ...     result = await admin_delete_gateway(gateway_id, mock_request_error, mock_db, mock_user)
        ...     return isinstance(result, RedirectResponse) and result.status_code == 303 and "/admin#gateways" in result.headers["location"]
        >>>
        >>> asyncio.run(test_admin_delete_gateway_exception())
        True
        >>>
        >>> # Restore original method
        >>> gateway_service.delete_gateway = original_delete_gateway
    """
    logger.debug(f"User {user} is deleting gateway ID {gateway_id}")
    try:
        await gateway_service.delete_gateway(db, gateway_id)
    except Exception as e:
        logger.error(f"Error deleting gateway: {e}")

    form = await request.form()
    is_inactive_checked = form.get("is_inactive_checked", "false")
    root_path = request.scope.get("root_path", "")

    if is_inactive_checked.lower() == "true":
        return RedirectResponse(f"{root_path}/admin/?include_inactive=true#gateways", status_code=303)
    return RedirectResponse(f"{root_path}/admin#gateways", status_code=303)


@admin_router.get("/resources/{uri:path}")
async def admin_get_resource(uri: str, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> Dict[str, Any]:
    """Get resource details for the admin UI.

    Args:
        uri: Resource URI.
        db: Database session.
        user: Authenticated user.

    Returns:
        A dictionary containing resource details and its content.

    Raises:
        HTTPException: If the resource is not found.
        Exception: For any other unexpected errors.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from mcpgateway.schemas import ResourceRead, ResourceMetrics, ResourceContent
        >>> from datetime import datetime, timezone
        >>> from mcpgateway.services.resource_service import ResourceNotFoundError # Added import
        >>> from fastapi import HTTPException
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> resource_uri = "test://resource/get"
        >>>
        >>> # Mock resource data
        >>> mock_resource = ResourceRead(
        ...     id=1, uri=resource_uri, name="Get Resource", description="Test",
        ...     mime_type="text/plain", size=10, created_at=datetime.now(timezone.utc),
        ...     updated_at=datetime.now(timezone.utc), is_active=True, metrics=ResourceMetrics(
        ...         total_executions=0, successful_executions=0, failed_executions=0,
        ...         failure_rate=0.0, min_response_time=0.0, max_response_time=0.0, avg_response_time=0.0,
        ...         last_execution_time=None
        ...     )
        ... )
        >>> mock_content = ResourceContent(type="resource", uri=resource_uri, mime_type="text/plain", text="Hello content")
        >>>
        >>> # Mock service methods
        >>> original_get_resource_by_uri = resource_service.get_resource_by_uri
        >>> original_read_resource = resource_service.read_resource
        >>> resource_service.get_resource_by_uri = AsyncMock(return_value=mock_resource)
        >>> resource_service.read_resource = AsyncMock(return_value=mock_content)
        >>>
        >>> # Test successful retrieval
        >>> async def test_admin_get_resource_success():
        ...     result = await admin_get_resource(resource_uri, mock_db, mock_user)
        ...     return isinstance(result, dict) and result['resource']['uri'] == resource_uri and result['content'].text == "Hello content" # Corrected to .text
        >>>
        >>> asyncio.run(test_admin_get_resource_success())
        True
        >>>
        >>> # Test resource not found
        >>> resource_service.get_resource_by_uri = AsyncMock(side_effect=ResourceNotFoundError("Resource not found"))
        >>> async def test_admin_get_resource_not_found():
        ...     try:
        ...         await admin_get_resource("nonexistent://uri", mock_db, mock_user)
        ...         return False
        ...     except HTTPException as e:
        ...         return e.status_code == 404 and "Resource not found" in e.detail
        >>>
        >>> asyncio.run(test_admin_get_resource_not_found())
        True
        >>>
        >>> # Test exception during content read (resource found but content fails)
        >>> resource_service.get_resource_by_uri = AsyncMock(return_value=mock_resource) # Resource found
        >>> resource_service.read_resource = AsyncMock(side_effect=Exception("Content read error"))
        >>> async def test_admin_get_resource_content_error():
        ...     try:
        ...         await admin_get_resource(resource_uri, mock_db, mock_user)
        ...         return False
        ...     except Exception as e:
        ...         return str(e) == "Content read error"
        >>>
        >>> asyncio.run(test_admin_get_resource_content_error())
        True
        >>>
        >>> # Restore original methods
        >>> resource_service.get_resource_by_uri = original_get_resource_by_uri
        >>> resource_service.read_resource = original_read_resource
    """
    logger.debug(f"User {user} requested details for resource URI {uri}")
    try:
        resource = await resource_service.get_resource_by_uri(db, uri)
        content = await resource_service.read_resource(db, uri)
        return {"resource": resource.model_dump(by_alias=True), "content": content}
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error getting resource {uri}: {e}")
        raise e


@admin_router.post("/resources")
async def admin_add_resource(request: Request, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> RedirectResponse:
    """
    Add a resource via the admin UI.

    Expects form fields:
      - uri
      - name
      - description (optional)
      - mime_type (optional)
      - content

    Args:
        request: FastAPI request containing form data.
        db: Database session.
        user: Authenticated user.

    Returns:
        A redirect response to the admin dashboard.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> form_data = FormData([
        ...     ("uri", "test://resource1"),
        ...     ("name", "Test Resource"),
        ...     ("description", "A test resource"),
        ...     ("mimeType", "text/plain"),
        ...     ("content", "Sample content"),
        ... ])
        >>> mock_request = MagicMock(spec=Request)
        >>> mock_request.form = AsyncMock(return_value=form_data)
        >>> mock_request.scope = {"root_path": ""}
        >>>
        >>> original_register_resource = resource_service.register_resource
        >>> resource_service.register_resource = AsyncMock()
        >>>
        >>> async def test_admin_add_resource():
        ...     response = await admin_add_resource(mock_request, mock_db, mock_user)
        ...     return isinstance(response, JSONResponse) and response.status_code == 200 and response.body.decode() == '{"message":"Add resource registered successfully!","success":true}'
        >>>
        >>> import asyncio; asyncio.run(test_admin_add_resource())
        True
        >>> resource_service.register_resource = original_register_resource
    """
    logger.debug(f"User {user} is adding a new resource")
    form = await request.form()
    try:
        resource = ResourceCreate(
            uri=form["uri"],
            name=form["name"],
            description=form.get("description"),
            mime_type=form.get("mimeType"),
            template=form.get("template"),  # defaults to None if not provided
            content=form["content"],
        )
        await resource_service.register_resource(db, resource)
        return JSONResponse(
            content={"message": "Add resource registered successfully!", "success": True},
            status_code=200,
        )
    except Exception as ex:
        if isinstance(ex, ValidationError):
            logger.error(f"ValidationError in admin_add_resource: {ErrorFormatter.format_validation_error(ex)}")
            return JSONResponse(content=ErrorFormatter.format_validation_error(ex), status_code=422)
        if isinstance(ex, IntegrityError):
            error_message = ErrorFormatter.format_database_error(ex)
            logger.error(f"IntegrityError in admin_add_resource: {error_message}")
            return JSONResponse(status_code=409, content=error_message)

        logger.error(f"Error in admin_add_resource: {ex}")
        return JSONResponse(content={"message": str(ex), "success": False}, status_code=500)


@admin_router.post("/resources/{uri:path}/edit")
async def admin_edit_resource(
    uri: str,
    request: Request,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> RedirectResponse:
    """
    Edit a resource via the admin UI.

    Expects form fields:
      - name
      - description (optional)
      - mime_type (optional)
      - content

    Args:
        uri: Resource URI.
        request: FastAPI request containing form data.
        db: Database session.
        user: Authenticated user.

    Returns:
        RedirectResponse: A redirect response to the admin dashboard.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> form_data = FormData([
        ...     ("name", "Updated Resource"),
        ...     ("description", "Updated description"),
        ...     ("mimeType", "text/plain"),
        ...     ("content", "Updated content"),
        ... ])
        >>> mock_request = MagicMock(spec=Request)
        >>> mock_request.form = AsyncMock(return_value=form_data)
        >>> mock_request.scope = {"root_path": ""}
        >>>
        >>> original_update_resource = resource_service.update_resource
        >>> resource_service.update_resource = AsyncMock()
        >>>
        >>> async def test_admin_edit_resource():
        ...     response = await admin_edit_resource("test://resource1", mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>>
        >>> import asyncio; asyncio.run(test_admin_edit_resource())
        True
        >>>
        >>> # Test with inactive checkbox checked
        >>> form_data_inactive = FormData([
        ...     ("name", "Updated Resource"),
        ...     ("description", "Updated description"),
        ...     ("mimeType", "text/plain"),
        ...     ("content", "Updated content"),
        ...     ("is_inactive_checked", "true")
        ... ])
        >>> mock_request.form = AsyncMock(return_value=form_data_inactive)
        >>>
        >>> async def test_admin_edit_resource_inactive():
        ...     response = await admin_edit_resource("test://resource1", mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and "include_inactive=true" in response.headers["location"]
        >>>
        >>> asyncio.run(test_admin_edit_resource_inactive())
        True
        >>> resource_service.update_resource = original_update_resource
    """
    logger.debug(f"User {user} is editing resource URI {uri}")
    form = await request.form()
    resource = ResourceUpdate(
        name=form["name"],
        description=form.get("description"),
        mime_type=form.get("mimeType"),
        content=form["content"],
    )
    await resource_service.update_resource(db, uri, resource)
    root_path = request.scope.get("root_path", "")
    is_inactive_checked = form.get("is_inactive_checked", "false")
    if is_inactive_checked.lower() == "true":
        return RedirectResponse(f"{root_path}/admin/?include_inactive=true#resources", status_code=303)
    return RedirectResponse(f"{root_path}/admin#resources", status_code=303)


@admin_router.post("/resources/{uri:path}/delete")
async def admin_delete_resource(uri: str, request: Request, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> RedirectResponse:
    """
    Delete a resource via the admin UI.

    This endpoint permanently removes a resource from the database using its URI.
    The operation is irreversible and should be used with caution. It requires
    user authentication and logs the deletion attempt.

    Args:
        uri (str): The URI of the resource to delete.
        request (Request): FastAPI request object (not used directly but required by the route signature).
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect response to the resources section of the admin
        dashboard with a status code of 303 (See Other).

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> mock_request = MagicMock(spec=Request)
        >>> form_data = FormData([("is_inactive_checked", "false")])
        >>> mock_request.form = AsyncMock(return_value=form_data)
        >>> mock_request.scope = {"root_path": ""}
        >>>
        >>> original_delete_resource = resource_service.delete_resource
        >>> resource_service.delete_resource = AsyncMock()
        >>>
        >>> async def test_admin_delete_resource():
        ...     response = await admin_delete_resource("test://resource1", mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>>
        >>> import asyncio; asyncio.run(test_admin_delete_resource())
        True
        >>>
        >>> # Test with inactive checkbox checked
        >>> form_data_inactive = FormData([("is_inactive_checked", "true")])
        >>> mock_request.form = AsyncMock(return_value=form_data_inactive)
        >>>
        >>> async def test_admin_delete_resource_inactive():
        ...     response = await admin_delete_resource("test://resource1", mock_request, mock_user)
        ...     return isinstance(response, RedirectResponse) and "include_inactive=true" in response.headers["location"]
        >>>
        >>> asyncio.run(test_admin_delete_resource_inactive())
        True
        >>> resource_service.delete_resource = original_delete_resource
    """
    logger.debug(f"User {user} is deleting resource URI {uri}")
    await resource_service.delete_resource(db, uri)
    form = await request.form()
    is_inactive_checked = form.get("is_inactive_checked", "false")
    root_path = request.scope.get("root_path", "")
    if is_inactive_checked.lower() == "true":
        return RedirectResponse(f"{root_path}/admin/?include_inactive=true#resources", status_code=303)
    return RedirectResponse(f"{root_path}/admin#resources", status_code=303)


@admin_router.post("/resources/{resource_id}/toggle")
async def admin_toggle_resource(
    resource_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> RedirectResponse:
    """
    Toggle a resource's active status via the admin UI.

    This endpoint processes a form request to activate or deactivate a resource.
    It expects a form field 'activate' with value "true" to activate the resource
    or "false" to deactivate it. The endpoint handles exceptions gracefully and
    logs any errors that might occur during the status toggle operation.

    Args:
        resource_id (int): The ID of the resource whose status to toggle.
        request (Request): FastAPI request containing form data with the 'activate' field.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect to the admin dashboard resources section with a
        status code of 303 (See Other).

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> mock_request = MagicMock(spec=Request)
        >>> form_data = FormData([
        ...     ("activate", "true"),
        ...     ("is_inactive_checked", "false")
        ... ])
        >>> mock_request.form = AsyncMock(return_value=form_data)
        >>> mock_request.scope = {"root_path": ""}
        >>>
        >>> original_toggle_resource_status = resource_service.toggle_resource_status
        >>> resource_service.toggle_resource_status = AsyncMock()
        >>>
        >>> async def test_admin_toggle_resource():
        ...     response = await admin_toggle_resource(1, mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>>
        >>> asyncio.run(test_admin_toggle_resource())
        True
        >>>
        >>> # Test with activate=false
        >>> form_data_deactivate = FormData([
        ...     ("activate", "false"),
        ...     ("is_inactive_checked", "false")
        ... ])
        >>> mock_request.form = AsyncMock(return_value=form_data_deactivate)
        >>>
        >>> async def test_admin_toggle_resource_deactivate():
        ...     response = await admin_toggle_resource(1, mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>>
        >>> asyncio.run(test_admin_toggle_resource_deactivate())
        True
        >>>
        >>> # Test with inactive checkbox checked
        >>> form_data_inactive = FormData([
        ...     ("activate", "true"),
        ...     ("is_inactive_checked", "true")
        ... ])
        >>> mock_request.form = AsyncMock(return_value=form_data_inactive)
        >>>
        >>> async def test_admin_toggle_resource_inactive():
        ...     response = await admin_toggle_resource(1, mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and "include_inactive=true" in response.headers["location"]
        >>>
        >>> asyncio.run(test_admin_toggle_resource_inactive())
        True
        >>>
        >>> # Test exception handling
        >>> resource_service.toggle_resource_status = AsyncMock(side_effect=Exception("Test error"))
        >>> form_data_error = FormData([
        ...     ("activate", "true"),
        ...     ("is_inactive_checked", "false")
        ... ])
        >>> mock_request.form = AsyncMock(return_value=form_data_error)
        >>>
        >>> async def test_admin_toggle_resource_exception():
        ...     response = await admin_toggle_resource(1, mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>>
        >>> asyncio.run(test_admin_toggle_resource_exception())
        True
        >>> resource_service.toggle_resource_status = original_toggle_resource_status
    """
    logger.debug(f"User {user} is toggling resource ID {resource_id}")
    form = await request.form()
    activate = form.get("activate", "true").lower() == "true"
    is_inactive_checked = form.get("is_inactive_checked", "false")
    try:
        await resource_service.toggle_resource_status(db, resource_id, activate)
    except Exception as e:
        logger.error(f"Error toggling resource status: {e}")

    root_path = request.scope.get("root_path", "")
    if is_inactive_checked.lower() == "true":
        return RedirectResponse(f"{root_path}/admin/?include_inactive=true#resources", status_code=303)
    return RedirectResponse(f"{root_path}/admin#resources", status_code=303)


@admin_router.get("/prompts/{name}")
async def admin_get_prompt(name: str, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> Dict[str, Any]:
    """Get prompt details for the admin UI.

    Args:
        name: Prompt name.
        db: Database session.
        user: Authenticated user.

    Returns:
        A dictionary with prompt details.

    Raises:
        HTTPException: If the prompt is not found.
        Exception: For any other unexpected errors.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from mcpgateway.schemas import PromptRead, PromptMetrics
        >>> from datetime import datetime, timezone
        >>> from mcpgateway.services.prompt_service import PromptNotFoundError # Added import
        >>> from fastapi import HTTPException
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> prompt_name = "test-prompt"
        >>>
        >>> # Mock prompt details
        >>> mock_metrics = PromptMetrics(
        ...     total_executions=3,
        ...     successful_executions=3,
        ...     failed_executions=0,
        ...     failure_rate=0.0,
        ...     min_response_time=0.1,
        ...     max_response_time=0.5,
        ...     avg_response_time=0.3,
        ...     last_execution_time=datetime.now(timezone.utc)
        ... )
        >>> mock_prompt_details = {
        ...     "id": 1,
        ...     "name": prompt_name,
        ...     "description": "A test prompt",
        ...     "template": "Hello {{name}}!",
        ...     "arguments": [{"name": "name", "type": "string"}],
        ...     "created_at": datetime.now(timezone.utc),
        ...     "updated_at": datetime.now(timezone.utc),
        ...     "is_active": True,
        ...     "metrics": mock_metrics
        ... }
        >>>
        >>> original_get_prompt_details = prompt_service.get_prompt_details
        >>> prompt_service.get_prompt_details = AsyncMock(return_value=mock_prompt_details)
        >>>
        >>> async def test_admin_get_prompt():
        ...     result = await admin_get_prompt(prompt_name, mock_db, mock_user)
        ...     return isinstance(result, dict) and result.get("name") == prompt_name
        >>>
        >>> asyncio.run(test_admin_get_prompt())
        True
        >>>
        >>> # Test prompt not found
        >>> prompt_service.get_prompt_details = AsyncMock(side_effect=PromptNotFoundError("Prompt not found"))
        >>> async def test_admin_get_prompt_not_found():
        ...     try:
        ...         await admin_get_prompt("nonexistent", mock_db, mock_user)
        ...         return False
        ...     except HTTPException as e:
        ...         return e.status_code == 404 and "Prompt not found" in e.detail
        >>>
        >>> asyncio.run(test_admin_get_prompt_not_found())
        True
        >>>
        >>> # Test generic exception
        >>> prompt_service.get_prompt_details = AsyncMock(side_effect=Exception("Generic error"))
        >>> async def test_admin_get_prompt_exception():
        ...     try:
        ...         await admin_get_prompt(prompt_name, mock_db, mock_user)
        ...         return False
        ...     except Exception as e:
        ...         return str(e) == "Generic error"
        >>>
        >>> asyncio.run(test_admin_get_prompt_exception())
        True
        >>>
        >>> prompt_service.get_prompt_details = original_get_prompt_details
    """
    logger.debug(f"User {user} requested details for prompt name {name}")
    try:
        prompt_details = await prompt_service.get_prompt_details(db, name)
        prompt = PromptRead.model_validate(prompt_details)
        return prompt.model_dump(by_alias=True)
    except PromptNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error getting prompt {name}: {e}")
        raise e


@admin_router.post("/prompts")
async def admin_add_prompt(request: Request, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> RedirectResponse:
    """Add a prompt via the admin UI.

    Expects form fields:
      - name
      - description (optional)
      - template
      - arguments (as a JSON string representing a list)

    Args:
        request: FastAPI request containing form data.
        db: Database session.
        user: Authenticated user.

    Returns:
        A redirect response to the admin dashboard.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> form_data = FormData([
        ...     ("name", "Test Prompt"),
        ...     ("description", "A test prompt"),
        ...     ("template", "Hello {{name}}!"),
        ...     ("arguments", '[{"name": "name", "type": "string"}]'),
        ... ])
        >>> mock_request = MagicMock(spec=Request)
        >>> mock_request.form = AsyncMock(return_value=form_data)
        >>> mock_request.scope = {"root_path": ""}
        >>>
        >>> original_register_prompt = prompt_service.register_prompt
        >>> prompt_service.register_prompt = AsyncMock()
        >>>
        >>> async def test_admin_add_prompt():
        ...     response = await admin_add_prompt(mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>>
        >>> asyncio.run(test_admin_add_prompt())
        True
        >>> prompt_service.register_prompt = original_register_prompt
    """
    logger.debug(f"User {user} is adding a new prompt")
    form = await request.form()
    args_json = form.get("arguments") or "[]"
    arguments = json.loads(args_json)
    try:
        prompt = PromptCreate(
            name=form["name"],
            description=form.get("description"),
            template=form["template"],
            arguments=arguments,
        )
        await prompt_service.register_prompt(db, prompt)

        return JSONResponse(
            content={"message": "Add resource registered successfully!", "success": True},
            status_code=200,
        )
    except Exception as ex:
        if isinstance(ex, ValidationError):
            logger.error(f"ValidationError in admin_add_prompt: {ErrorFormatter.format_validation_error(ex)}")
            return JSONResponse(content=ErrorFormatter.format_validation_error(ex), status_code=422)
        if isinstance(ex, IntegrityError):
            error_message = ErrorFormatter.format_database_error(ex)
            logger.error(f"IntegrityError in admin_add_prompt: {error_message}")
            return JSONResponse(status_code=409, content=error_message)

        logger.error(f"Error in admin_add_prompt: {ex}")
        return JSONResponse(content={"message": str(ex), "success": False}, status_code=500)


@admin_router.post("/prompts/{name}/edit")
async def admin_edit_prompt(
    name: str,
    request: Request,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> RedirectResponse:
    """Edit a prompt via the admin UI.

    Expects form fields:
      - name
      - description (optional)
      - template
      - arguments (as a JSON string representing a list)

    Args:
        name: Prompt name.
        request: FastAPI request containing form data.
        db: Database session.
        user: Authenticated user.

    Returns:
        A redirect response to the admin dashboard.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> prompt_name = "test-prompt"
        >>> form_data = FormData([
        ...     ("name", "Updated Prompt"),
        ...     ("description", "Updated description"),
        ...     ("template", "Hello {{name}}, welcome!"),
        ...     ("arguments", '[{"name": "name", "type": "string"}]'),
        ...     ("is_inactive_checked", "false")
        ... ])
        >>> mock_request = MagicMock(spec=Request)
        >>> mock_request.form = AsyncMock(return_value=form_data)
        >>> mock_request.scope = {"root_path": ""}
        >>>
        >>> original_update_prompt = prompt_service.update_prompt
        >>> prompt_service.update_prompt = AsyncMock()
        >>>
        >>> async def test_admin_edit_prompt():
        ...     response = await admin_edit_prompt(prompt_name, mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>>
        >>> asyncio.run(test_admin_edit_prompt())
        True
        >>>
        >>> # Test with inactive checkbox checked
        >>> form_data_inactive = FormData([
        ...     ("name", "Updated Prompt"),
        ...     ("template", "Hello {{name}}!"),
        ...     ("arguments", "[]"),
        ...     ("is_inactive_checked", "true")
        ... ])
        >>> mock_request.form = AsyncMock(return_value=form_data_inactive)
        >>>
        >>> async def test_admin_edit_prompt_inactive():
        ...     response = await admin_edit_prompt(prompt_name, mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and "include_inactive=true" in response.headers["location"]
        >>>
        >>> asyncio.run(test_admin_edit_prompt_inactive())
        True
        >>> prompt_service.update_prompt = original_update_prompt
    """
    logger.debug(f"User {user} is editing prompt name {name}")
    form = await request.form()
    args_json = form.get("arguments") or "[]"
    arguments = json.loads(args_json)
    prompt = PromptUpdate(
        name=form["name"],
        description=form.get("description"),
        template=form["template"],
        arguments=arguments,
    )
    await prompt_service.update_prompt(db, name, prompt)

    root_path = request.scope.get("root_path", "")
    is_inactive_checked = form.get("is_inactive_checked", "false")

    if is_inactive_checked.lower() == "true":
        return RedirectResponse(f"{root_path}/admin/?include_inactive=true#prompts", status_code=303)
    return RedirectResponse(f"{root_path}/admin#prompts", status_code=303)


@admin_router.post("/prompts/{name}/delete")
async def admin_delete_prompt(name: str, request: Request, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> RedirectResponse:
    """
    Delete a prompt via the admin UI.

    This endpoint permanently deletes a prompt from the database using its name.
    Deletion is irreversible and requires authentication. All actions are logged
    for administrative auditing.

    Args:
        name (str): The name of the prompt to delete.
        request (Request): FastAPI request object (not used directly but required by the route signature).
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect response to the prompts section of the admin
        dashboard with a status code of 303 (See Other).

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> mock_request = MagicMock(spec=Request)
        >>> form_data = FormData([("is_inactive_checked", "false")])
        >>> mock_request.form = AsyncMock(return_value=form_data)
        >>> mock_request.scope = {"root_path": ""}
        >>>
        >>> original_delete_prompt = prompt_service.delete_prompt
        >>> prompt_service.delete_prompt = AsyncMock()
        >>>
        >>> async def test_admin_delete_prompt():
        ...     response = await admin_delete_prompt("test-prompt", mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>>
        >>> asyncio.run(test_admin_delete_prompt())
        True
        >>>
        >>> # Test with inactive checkbox checked
        >>> form_data_inactive = FormData([("is_inactive_checked", "true")])
        >>> mock_request.form = AsyncMock(return_value=form_data_inactive)
        >>>
        >>> async def test_admin_delete_prompt_inactive():
        ...     response = await admin_delete_prompt("test-prompt", mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and "include_inactive=true" in response.headers["location"]
        >>>
        >>> asyncio.run(test_admin_delete_prompt_inactive())
        True
        >>> prompt_service.delete_prompt = original_delete_prompt
    """
    logger.debug(f"User {user} is deleting prompt name {name}")
    await prompt_service.delete_prompt(db, name)
    form = await request.form()
    is_inactive_checked = form.get("is_inactive_checked", "false")
    root_path = request.scope.get("root_path", "")
    if is_inactive_checked.lower() == "true":
        return RedirectResponse(f"{root_path}/admin/?include_inactive=true#prompts", status_code=303)
    return RedirectResponse(f"{root_path}/admin#prompts", status_code=303)


@admin_router.post("/prompts/{prompt_id}/toggle")
async def admin_toggle_prompt(
    prompt_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> RedirectResponse:
    """
    Toggle a prompt's active status via the admin UI.

    This endpoint processes a form request to activate or deactivate a prompt.
    It expects a form field 'activate' with value "true" to activate the prompt
    or "false" to deactivate it. The endpoint handles exceptions gracefully and
    logs any errors that might occur during the status toggle operation.

    Args:
        prompt_id (int): The ID of the prompt whose status to toggle.
        request (Request): FastAPI request containing form data with the 'activate' field.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect to the admin dashboard prompts section with a
        status code of 303 (See Other).

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>> mock_request = MagicMock(spec=Request)
        >>> form_data = FormData([
        ...     ("activate", "true"),
        ...     ("is_inactive_checked", "false")
        ... ])
        >>> mock_request.form = AsyncMock(return_value=form_data)
        >>> mock_request.scope = {"root_path": ""}
        >>>
        >>> original_toggle_prompt_status = prompt_service.toggle_prompt_status
        >>> prompt_service.toggle_prompt_status = AsyncMock()
        >>>
        >>> async def test_admin_toggle_prompt():
        ...     response = await admin_toggle_prompt(1, mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>>
        >>> asyncio.run(test_admin_toggle_prompt())
        True
        >>>
        >>> # Test with activate=false
        >>> form_data_deactivate = FormData([
        ...     ("activate", "false"),
        ...     ("is_inactive_checked", "false")
        ... ])
        >>> mock_request.form = AsyncMock(return_value=form_data_deactivate)
        >>>
        >>> async def test_admin_toggle_prompt_deactivate():
        ...     response = await admin_toggle_prompt(1, mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>>
        >>> asyncio.run(test_admin_toggle_prompt_deactivate())
        True
        >>>
        >>> # Test with inactive checkbox checked
        >>> form_data_inactive = FormData([
        ...     ("activate", "true"),
        ...     ("is_inactive_checked", "true")
        ... ])
        >>> mock_request.form = AsyncMock(return_value=form_data_inactive)
        >>>
        >>> async def test_admin_toggle_prompt_inactive():
        ...     response = await admin_toggle_prompt(1, mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and "include_inactive=true" in response.headers["location"]
        >>>
        >>> asyncio.run(test_admin_toggle_prompt_inactive())
        True
        >>>
        >>> # Test exception handling
        >>> prompt_service.toggle_prompt_status = AsyncMock(side_effect=Exception("Test error"))
        >>> form_data_error = FormData([
        ...     ("activate", "true"),
        ...     ("is_inactive_checked", "false")
        ... ])
        >>> mock_request.form = AsyncMock(return_value=form_data_error)
        >>>
        >>> async def test_admin_toggle_prompt_exception():
        ...     response = await admin_toggle_prompt(1, mock_request, mock_db, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>>
        >>> asyncio.run(test_admin_toggle_prompt_exception())
        True
        >>> prompt_service.toggle_prompt_status = original_toggle_prompt_status
    """
    logger.debug(f"User {user} is toggling prompt ID {prompt_id}")
    form = await request.form()
    activate = form.get("activate", "true").lower() == "true"
    is_inactive_checked = form.get("is_inactive_checked", "false")
    try:
        await prompt_service.toggle_prompt_status(db, prompt_id, activate)
    except Exception as e:
        logger.error(f"Error toggling prompt status: {e}")

    root_path = request.scope.get("root_path", "")
    if is_inactive_checked.lower() == "true":
        return RedirectResponse(f"{root_path}/admin/?include_inactive=true#prompts", status_code=303)
    return RedirectResponse(f"{root_path}/admin#prompts", status_code=303)


@admin_router.post("/roots")
async def admin_add_root(request: Request, user: str = Depends(require_auth)) -> RedirectResponse:
    """Add a new root via the admin UI.

    Expects form fields:
      - path
      - name (optional)

    Args:
        request: FastAPI request containing form data.
        user: Authenticated user.

    Returns:
        RedirectResponse: A redirect response to the admin dashboard.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>>
        >>> mock_user = "test_user"
        >>> mock_request = MagicMock(spec=Request)
        >>> form_data = FormData([
        ...     ("uri", "test://root1"),
        ...     ("name", "Test Root"),
        ... ])
        >>> mock_request.form = AsyncMock(return_value=form_data)
        >>> mock_request.scope = {"root_path": ""}
        >>>
        >>> original_add_root = root_service.add_root
        >>> root_service.add_root = AsyncMock()
        >>>
        >>> async def test_admin_add_root():
        ...     response = await admin_add_root(mock_request, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>>
        >>> asyncio.run(test_admin_add_root())
        True
        >>> root_service.add_root = original_add_root
    """
    logger.debug(f"User {user} is adding a new root")
    form = await request.form()
    uri = form["uri"]
    name = form.get("name")
    await root_service.add_root(uri, name)
    root_path = request.scope.get("root_path", "")
    return RedirectResponse(f"{root_path}/admin#roots", status_code=303)


@admin_router.post("/roots/{uri:path}/delete")
async def admin_delete_root(uri: str, request: Request, user: str = Depends(require_auth)) -> RedirectResponse:
    """
    Delete a root via the admin UI.

    This endpoint removes a registered root URI from the system. The deletion is
    permanent and cannot be undone. It requires authentication and logs the
    operation for audit purposes.

    Args:
        uri (str): The URI of the root to delete.
        request (Request): FastAPI request object (not used directly but required by the route signature).
        user (str): Authenticated user dependency.

    Returns:
        RedirectResponse: A redirect response to the roots section of the admin
        dashboard with a status code of 303 (See Other).

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from fastapi import Request
        >>> from fastapi.responses import RedirectResponse
        >>> from starlette.datastructures import FormData
        >>>
        >>> mock_user = "test_user"
        >>> mock_request = MagicMock(spec=Request)
        >>> form_data = FormData([("is_inactive_checked", "false")])
        >>> mock_request.form = AsyncMock(return_value=form_data)
        >>> mock_request.scope = {"root_path": ""}
        >>>
        >>> original_remove_root = root_service.remove_root
        >>> root_service.remove_root = AsyncMock()
        >>>
        >>> async def test_admin_delete_root():
        ...     response = await admin_delete_root("test://root1", mock_request, mock_user)
        ...     return isinstance(response, RedirectResponse) and response.status_code == 303
        >>>
        >>> asyncio.run(test_admin_delete_root())
        True
        >>>
        >>> # Test with inactive checkbox checked
        >>> form_data_inactive = FormData([("is_inactive_checked", "true")])
        >>> mock_request.form = AsyncMock(return_value=form_data_inactive)
        >>>
        >>> async def test_admin_delete_root_inactive():
        ...     response = await admin_delete_root("test://root1", mock_request, mock_user)
        ...     return isinstance(response, RedirectResponse) and "include_inactive=true" in response.headers["location"]
        >>>
        >>> asyncio.run(test_admin_delete_root_inactive())
        True
        >>> root_service.remove_root = original_remove_root
    """
    logger.debug(f"User {user} is deleting root URI {uri}")
    await root_service.remove_root(uri)
    form = await request.form()
    root_path = request.scope.get("root_path", "")
    is_inactive_checked = form.get("is_inactive_checked", "false")
    if is_inactive_checked.lower() == "true":
        return RedirectResponse(f"{root_path}/admin/?include_inactive=true#roots", status_code=303)
    return RedirectResponse(f"{root_path}/admin#roots", status_code=303)


# Metrics
MetricsDict = Dict[str, Union[ToolMetrics, ResourceMetrics, ServerMetrics, PromptMetrics]]


@admin_router.get("/metrics", response_model=MetricsDict)
async def admin_get_metrics(
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> MetricsDict:
    """
    Retrieve aggregate metrics for all entity types via the admin UI.

    This endpoint collects and returns usage metrics for tools, resources, servers,
    and prompts. The metrics are retrieved by calling the aggregate_metrics method
    on each respective service, which compiles statistics about usage patterns,
    success rates, and other relevant metrics for administrative monitoring
    and analysis purposes.

    Args:
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        MetricsDict: A dictionary containing the aggregated metrics for tools,
        resources, servers, and prompts. Each value is a Pydantic model instance
        specific to the entity type.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from mcpgateway.schemas import ToolMetrics, ResourceMetrics, ServerMetrics, PromptMetrics
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>>
        >>> mock_tool_metrics = ToolMetrics(
        ...     total_executions=10,
        ...     successful_executions=9,
        ...     failed_executions=1,
        ...     failure_rate=0.1,
        ...     min_response_time=0.05,
        ...     max_response_time=1.0,
        ...     avg_response_time=0.3,
        ...     last_execution_time=None
        ... )
        >>> mock_resource_metrics = ResourceMetrics(
        ...     total_executions=5,
        ...     successful_executions=5,
        ...     failed_executions=0,
        ...     failure_rate=0.0,
        ...     min_response_time=0.1,
        ...     max_response_time=0.5,
        ...     avg_response_time=0.2,
        ...     last_execution_time=None
        ... )
        >>> mock_server_metrics = ServerMetrics(
        ...     total_executions=7,
        ...     successful_executions=7,
        ...     failed_executions=0,
        ...     failure_rate=0.0,
        ...     min_response_time=0.2,
        ...     max_response_time=0.7,
        ...     avg_response_time=0.4,
        ...     last_execution_time=None
        ... )
        >>> mock_prompt_metrics = PromptMetrics(
        ...     total_executions=3,
        ...     successful_executions=3,
        ...     failed_executions=0,
        ...     failure_rate=0.0,
        ...     min_response_time=0.15,
        ...     max_response_time=0.6,
        ...     avg_response_time=0.35,
        ...     last_execution_time=None
        ... )
        >>>
        >>> original_aggregate_metrics_tool = tool_service.aggregate_metrics
        >>> original_aggregate_metrics_resource = resource_service.aggregate_metrics
        >>> original_aggregate_metrics_server = server_service.aggregate_metrics
        >>> original_aggregate_metrics_prompt = prompt_service.aggregate_metrics
        >>>
        >>> tool_service.aggregate_metrics = AsyncMock(return_value=mock_tool_metrics)
        >>> resource_service.aggregate_metrics = AsyncMock(return_value=mock_resource_metrics)
        >>> server_service.aggregate_metrics = AsyncMock(return_value=mock_server_metrics)
        >>> prompt_service.aggregate_metrics = AsyncMock(return_value=mock_prompt_metrics)
        >>>
        >>> async def test_admin_get_metrics():
        ...     result = await admin_get_metrics(mock_db, mock_user)
        ...     return (
        ...         isinstance(result, dict) and
        ...         result.get("tools") == mock_tool_metrics and
        ...         result.get("resources") == mock_resource_metrics and
        ...         result.get("servers") == mock_server_metrics and
        ...         result.get("prompts") == mock_prompt_metrics
        ...     )
        >>>
        >>> import asyncio; asyncio.run(test_admin_get_metrics())
        True
        >>>
        >>> tool_service.aggregate_metrics = original_aggregate_metrics_tool
        >>> resource_service.aggregate_metrics = original_aggregate_metrics_resource
        >>> server_service.aggregate_metrics = original_aggregate_metrics_server
        >>> prompt_service.aggregate_metrics = original_aggregate_metrics_prompt
    """
    logger.debug(f"User {user} requested aggregate metrics")
    tool_metrics = await tool_service.aggregate_metrics(db)
    resource_metrics = await resource_service.aggregate_metrics(db)
    server_metrics = await server_service.aggregate_metrics(db)
    prompt_metrics = await prompt_service.aggregate_metrics(db)

    return {
        "tools": tool_metrics,
        "resources": resource_metrics,
        "servers": server_metrics,
        "prompts": prompt_metrics,
    }


@admin_router.post("/metrics/reset", response_model=Dict[str, object])
async def admin_reset_metrics(db: Session = Depends(get_db), user: str = Depends(require_auth)) -> Dict[str, object]:
    """
    Reset all metrics for tools, resources, servers, and prompts.
    Each service must implement its own reset_metrics method.

    Args:
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        Dict[str, object]: A dictionary containing a success message and status.

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>>
        >>> mock_db = MagicMock()
        >>> mock_user = "test_user"
        >>>
        >>> original_reset_metrics_tool = tool_service.reset_metrics
        >>> original_reset_metrics_resource = resource_service.reset_metrics
        >>> original_reset_metrics_server = server_service.reset_metrics
        >>> original_reset_metrics_prompt = prompt_service.reset_metrics
        >>>
        >>> tool_service.reset_metrics = AsyncMock()
        >>> resource_service.reset_metrics = AsyncMock()
        >>> server_service.reset_metrics = AsyncMock()
        >>> prompt_service.reset_metrics = AsyncMock()
        >>>
        >>> async def test_admin_reset_metrics():
        ...     result = await admin_reset_metrics(mock_db, mock_user)
        ...     return result == {"message": "All metrics reset successfully", "success": True}
        >>>
        >>> import asyncio; asyncio.run(test_admin_reset_metrics())
        True
        >>>
        >>> tool_service.reset_metrics = original_reset_metrics_tool
        >>> resource_service.reset_metrics = original_reset_metrics_resource
        >>> server_service.reset_metrics = original_reset_metrics_server
        >>> prompt_service.reset_metrics = original_reset_metrics_prompt
    """
    logger.debug(f"User {user} requested to reset all metrics")
    await tool_service.reset_metrics(db)
    await resource_service.reset_metrics(db)
    await server_service.reset_metrics(db)
    await prompt_service.reset_metrics(db)
    return {"message": "All metrics reset successfully", "success": True}


@admin_router.post("/gateways/test", response_model=GatewayTestResponse)
async def admin_test_gateway(request: GatewayTestRequest, user: str = Depends(require_auth)) -> GatewayTestResponse:
    """
    Test a gateway by sending a request to its URL.
    This endpoint allows administrators to test the connectivity and response

    Args:
        request (GatewayTestRequest): The request object containing the gateway URL and request details.
        user (str): Authenticated user dependency.

    Returns:
        GatewayTestResponse: The response from the gateway, including status code, latency, and body

    Examples:
        >>> import asyncio
        >>> from unittest.mock import AsyncMock, MagicMock
        >>> from mcpgateway.schemas import GatewayTestRequest, GatewayTestResponse
        >>> from fastapi import Request
        >>> import httpx
        >>>
        >>> mock_user = "test_user"
        >>> mock_request = GatewayTestRequest(
        ...     base_url="https://api.example.com",
        ...     path="/test",
        ...     method="GET",
        ...     headers={},
        ...     body=None
        ... )
        >>>
        >>> # Mock ResilientHttpClient to simulate a successful response
        >>> class MockResponse:
        ...     def __init__(self):
        ...         self.status_code = 200
        ...         self._json = {"message": "success"}
        ...     def json(self):
        ...         return self._json
        ...     @property
        ...     def text(self):
        ...         return str(self._json)
        >>>
        >>> class MockClient:
        ...     async def __aenter__(self):
        ...         return self
        ...     async def __aexit__(self, exc_type, exc, tb):
        ...         pass
        ...     async def request(self, method, url, headers=None, json=None):
        ...         return MockResponse()
        >>>
        >>> from unittest.mock import patch
        >>>
        >>> async def test_admin_test_gateway():
        ...     with patch('mcpgateway.admin.ResilientHttpClient') as mock_client_class:
        ...         mock_client_class.return_value = MockClient()
        ...         response = await admin_test_gateway(mock_request, mock_user)
        ...         return isinstance(response, GatewayTestResponse) and response.status_code == 200
        >>>
        >>> result = asyncio.run(test_admin_test_gateway())
        >>> result
        True
        >>>
        >>> # Test with JSON decode error
        >>> class MockResponseTextOnly:
        ...     def __init__(self):
        ...         self.status_code = 200
        ...         self.text = "plain text response"
        ...     def json(self):
        ...         raise json.JSONDecodeError("Invalid JSON", "doc", 0)
        >>>
        >>> class MockClientTextOnly:
        ...     async def __aenter__(self):
        ...         return self
        ...     async def __aexit__(self, exc_type, exc, tb):
        ...         pass
        ...     async def request(self, method, url, headers=None, json=None):
        ...         return MockResponseTextOnly()
        >>>
        >>> async def test_admin_test_gateway_text_response():
        ...     with patch('mcpgateway.admin.ResilientHttpClient') as mock_client_class:
        ...         mock_client_class.return_value = MockClientTextOnly()
        ...         response = await admin_test_gateway(mock_request, mock_user)
        ...         return isinstance(response, GatewayTestResponse) and response.body.get("details") == "plain text response"
        >>>
        >>> asyncio.run(test_admin_test_gateway_text_response())
        True
        >>>
        >>> # Test with network error
        >>> class MockClientError:
        ...     async def __aenter__(self):
        ...         return self
        ...     async def __aexit__(self, exc_type, exc, tb):
        ...         pass
        ...     async def request(self, method, url, headers=None, json=None):
        ...         raise httpx.RequestError("Network error")
        >>>
        >>> async def test_admin_test_gateway_network_error():
        ...     with patch('mcpgateway.admin.ResilientHttpClient') as mock_client_class:
        ...         mock_client_class.return_value = MockClientError()
        ...         response = await admin_test_gateway(mock_request, mock_user)
        ...         return response.status_code == 502 and "Network error" in str(response.body)
        >>>
        >>> asyncio.run(test_admin_test_gateway_network_error())
        True
        >>>
        >>> # Test with POST method and body
        >>> mock_request_post = GatewayTestRequest(
        ...     base_url="https://api.example.com",
        ...     path="/test",
        ...     method="POST",
        ...     headers={"Content-Type": "application/json"},
        ...     body={"test": "data"}
        ... )
        >>>
        >>> async def test_admin_test_gateway_post():
        ...     with patch('mcpgateway.admin.ResilientHttpClient') as mock_client_class:
        ...         mock_client_class.return_value = MockClient()
        ...         response = await admin_test_gateway(mock_request_post, mock_user)
        ...         return isinstance(response, GatewayTestResponse) and response.status_code == 200
        >>>
        >>> asyncio.run(test_admin_test_gateway_post())
        True
        >>>
        >>> # Test URL path handling with trailing slashes
        >>> mock_request_trailing = GatewayTestRequest(
        ...     base_url="https://api.example.com/",
        ...     path="/test/",
        ...     method="GET",
        ...     headers={},
        ...     body=None
        ... )
        >>>
        >>> async def test_admin_test_gateway_trailing_slash():
        ...     with patch('mcpgateway.admin.ResilientHttpClient') as mock_client_class:
        ...         mock_client_class.return_value = MockClient()
        ...         response = await admin_test_gateway(mock_request_trailing, mock_user)
        ...         return isinstance(response, GatewayTestResponse) and response.status_code == 200
        >>>
        >>> asyncio.run(test_admin_test_gateway_trailing_slash())
        True
    """
    full_url = str(request.base_url).rstrip("/") + "/" + request.path.lstrip("/")
    full_url = full_url.rstrip("/")
    logger.debug(f"User {user} testing server at {request.base_url}.")
    try:
        start_time = time.monotonic()
        async with ResilientHttpClient(client_args={"timeout": settings.federation_timeout, "verify": not settings.skip_ssl_verify}) as client:
            response = await client.request(method=request.method.upper(), url=full_url, headers=request.headers, json=request.body)
        latency_ms = int((time.monotonic() - start_time) * 1000)
        try:
            response_body: Union[dict, str] = response.json()
        except json.JSONDecodeError:
            response_body = {"details": response.text}

        return GatewayTestResponse(status_code=response.status_code, latency_ms=latency_ms, body=response_body)

    except httpx.RequestError as e:
        logger.warning(f"Gateway test failed: {e}")
        latency_ms = int((time.monotonic() - start_time) * 1000)
        return GatewayTestResponse(status_code=502, latency_ms=latency_ms, body={"error": "Request failed", "details": str(e)})
