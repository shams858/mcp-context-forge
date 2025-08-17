# -*- coding: utf-8 -*-
"""OAuth Router for MCP Gateway.

This module handles OAuth 2.0 Authorization Code flow endpoints including:
- Initiating OAuth flows
- Handling OAuth callbacks
- Token management
"""

import logging
from typing import Optional, Dict, Any

from fastapi import APIRouter, Depends, Request, HTTPException, Query
from fastapi.responses import RedirectResponse, HTMLResponse
from sqlalchemy.orm import Session
from sqlalchemy import select

from mcpgateway.db import get_db, Gateway
from mcpgateway.services.oauth_manager import OAuthManager, OAuthError
from mcpgateway.services.token_storage_service import TokenStorageService

logger = logging.getLogger(__name__)

oauth_router = APIRouter(prefix="/oauth", tags=["oauth"])


@oauth_router.get("/authorize/{gateway_id}")
async def initiate_oauth_flow(
    gateway_id: str,
    request: Request,
    db: Session = Depends(get_db)
) -> RedirectResponse:
    """Initiate OAuth Authorization Code flow.

    Args:
        gateway_id: ID of the gateway to authorize
        request: FastAPI request object
        db: Database session

    Returns:
        Redirect response to OAuth provider
    """
    try:
        # Get gateway configuration
        gateway = db.execute(
            select(Gateway).where(Gateway.id == gateway_id)
        ).scalar_one_or_none()

        if not gateway:
            raise HTTPException(status_code=404, detail="Gateway not found")

        if not gateway.oauth_config:
            raise HTTPException(
                status_code=400,
                detail="Gateway is not configured for OAuth"
            )

        if gateway.oauth_config.get('grant_type') != 'authorization_code':
            raise HTTPException(
                status_code=400,
                detail="Gateway is not configured for Authorization Code flow"
            )

        # Initiate OAuth flow
        oauth_manager = OAuthManager(token_storage=TokenStorageService(db))
        auth_data = await oauth_manager.initiate_authorization_code_flow(
            gateway_id, gateway.oauth_config
        )

        logger.info(f"Initiated OAuth flow for gateway {gateway_id}")

        # Redirect user to OAuth provider
        return RedirectResponse(url=auth_data['authorization_url'])

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to initiate OAuth flow: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to initiate OAuth flow: {str(e)}"
        )


@oauth_router.get("/callback")
async def oauth_callback(
    code: str = Query(..., description="Authorization code from OAuth provider"),
    state: str = Query(..., description="State parameter for CSRF protection"),
    # Remove the gateway_id parameter requirement
    request: Request = None,
    db: Session = Depends(get_db)
) -> HTMLResponse:
    """Handle OAuth callback and complete authorization."""

    try:
        # Extract gateway_id from state parameter
        if '_' not in state:
            return HTMLResponse(
                content="<h1>❌ Invalid state parameter</h1>",
                status_code=400
            )

        gateway_id = state.split('_')[0]

        # Get gateway configuration
        gateway = db.execute(
            select(Gateway).where(Gateway.id == gateway_id)
        ).scalar_one_or_none()

        if not gateway:
            return HTMLResponse(
                content=f"""
                <!DOCTYPE html>
                <html>
                <head><title>OAuth Authorization Failed</title></head>
                <body>
                    <h1>❌ OAuth Authorization Failed</h1>
                    <p>Error: Gateway not found</p>
                    <a href="/admin#gateways">Return to Admin Panel</a>
                </body>
                </html>
                """,
                status_code=404
            )

        if not gateway.oauth_config:
            return HTMLResponse(
                content=f"""
                <!DOCTYPE html>
                <html>
                <head><title>OAuth Authorization Failed</title></head>
                <body>
                    <h1>❌ OAuth Authorization Failed</h1>
                    <p>Error: Gateway has no OAuth configuration</p>
                    <a href="/admin#gateways">Return to Admin Panel</a>
                </body>
                </html>
                """,
                status_code=400
            )

        # Complete OAuth flow
        oauth_manager = OAuthManager(token_storage=TokenStorageService(db))

        result = await oauth_manager.complete_authorization_code_flow(
            gateway_id, code, state, gateway.oauth_config
        )

        logger.info(f"Completed OAuth flow for gateway {gateway_id}, user {result.get('user_id')}")

        # Return success page with option to return to admin
        return HTMLResponse(content=f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>OAuth Authorization Successful</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .success {{ color: #059669; }}
                .error {{ color: #dc2626; }}
                .info {{ color: #2563eb; }}
                .button {{
                    display: inline-block;
                    padding: 10px 20px;
                    background-color: #3b82f6;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    margin-top: 20px;
                }}
                .button:hover {{ background-color: #2563eb; }}
            </style>
        </head>
        <body>
            <h1 class="success">✅ OAuth Authorization Successful</h1>
            <div class="info">
                <p><strong>Gateway:</strong> {gateway.name}</p>
                <p><strong>User ID:</strong> {result.get('user_id', 'Unknown')}</p>
                <p><strong>Expires:</strong> {result.get('expires_at', 'Unknown')}</p>
                <p><strong>Status:</strong> Authorization completed successfully</p>
            </div>

            <div style="margin: 30px 0;">
                <h3>Next Steps:</h3>
                <p>Now that OAuth authorization is complete, you can fetch tools from the MCP server:</p>
                <button onclick="fetchTools()" class="button" style="background-color: #059669;">
                    🔧 Fetch Tools from MCP Server
                </button>
                <div id="fetch-status" style="margin-top: 15px;"></div>
            </div>

            <a href="/admin#gateways" class="button">Return to Admin Panel</a>

            <script>
            async function fetchTools() {{
                const button = event.target;
                const statusDiv = document.getElementById('fetch-status');

                button.disabled = true;
                button.textContent = '⏳ Fetching Tools...';
                statusDiv.innerHTML = '<p style="color: #2563eb;">Fetching tools from MCP server...</p>';

                try {{
                    const response = await fetch('/oauth/fetch-tools/{gateway_id}', {{
                        method: 'POST'
                    }});

                    const result = await response.json();

                    if (response.ok) {{
                        statusDiv.innerHTML = `
                            <div style="color: #059669; padding: 15px; background-color: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 5px;">
                                <h4>✅ Tools Fetched Successfully!</h4>
                                <p><strong>Tools Created:</strong> ${{result.tools_created}}</p>
                                <p><strong>Resources:</strong> ${{result.resources}}</p>
                                <p><strong>Prompts:</strong> ${{result.prompts}}</p>
                                <p>${{result.message}}</p>
                            </div>
                        `;
                        button.textContent = '✅ Tools Fetched';
                        button.style.backgroundColor = '#059669';
                    }} else {{
                        throw new Error(result.detail || 'Failed to fetch tools');
                    }}
                }} catch (error) {{
                    statusDiv.innerHTML = `
                        <div style="color: #dc2626; padding: 15px; background-color: #fef2f2; border: 1px solid #fecaca; border-radius: 5px;">
                            <h4>❌ Failed to Fetch Tools</h4>
                            <p><strong>Error:</strong> ${{error.message}}</p>
                            <p>You can still return to the admin panel and try again later.</p>
                        </div>
                    `;
                    button.textContent = '❌ Retry Fetch Tools';
                    button.style.backgroundColor = '#dc2626';
                    button.disabled = false;
                }}
            }}
            </script>
        </body>
        </html>
        """)

    except OAuthError as e:
        logger.error(f"OAuth callback failed: {str(e)}")
        return HTMLResponse(content=f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>OAuth Authorization Failed</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .error {{ color: #dc2626; }}
                .button {{
                    display: inline-block;
                    padding: 10px 20px;
                    background-color: #3b82f6;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    margin-top: 20px;
                }}
                .button:hover {{ background-color: #2563eb; }}
            </style>
        </head>
        <body>
            <h1 class="error">❌ OAuth Authorization Failed</h1>
            <p><strong>Error:</strong> {str(e)}</p>
            <p>Please check your OAuth configuration and try again.</p>
            <a href="/admin#gateways" class="button">Return to Admin Panel</a>
        </body>
        </html>
        """, status_code=400)

    except Exception as e:
        logger.error(f"Unexpected error in OAuth callback: {str(e)}")
        return HTMLResponse(content=f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>OAuth Authorization Failed</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .error {{ color: #dc2626; }}
                .button {{
                    display: inline-block;
                    padding: 10px 20px;
                    background-color: #3b82f6;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    margin-top: 20px;
                }}
                .button:hover {{ background-color: #2563eb; }}
            </style>
        </head>
        <body>
            <h1 class="error">❌ OAuth Authorization Failed</h1>
            <p><strong>Unexpected Error:</strong> {str(e)}</p>
            <p>Please contact your administrator for assistance.</p>
            <a href="/admin#gateways" class="button">Return to Admin Panel</a>
        </body>
        </html>
        """, status_code=500)


@oauth_router.get("/status/{gateway_id}")
async def get_oauth_status(
    gateway_id: str,
    db: Session = Depends(get_db)
) -> dict:
    """Get OAuth status for a gateway.

    Args:
        gateway_id: ID of the gateway
        db: Database session

    Returns:
        OAuth status information
    """
    try:
        # Get gateway configuration
        gateway = db.execute(
            select(Gateway).where(Gateway.id == gateway_id)
        ).scalar_one_or_none()

        if not gateway:
            raise HTTPException(status_code=404, detail="Gateway not found")

        if not gateway.oauth_config:
            return {
                "oauth_enabled": False,
                "message": "Gateway is not configured for OAuth"
            }

        # Get OAuth configuration info
        oauth_config = gateway.oauth_config
        grant_type = oauth_config.get('grant_type')

        if grant_type == 'authorization_code':
            # Get token information if available
            token_storage = TokenStorageService(db)
            # For now, return basic info - in a real implementation you might want to
            # show authorized users, token status, etc.
            return {
                "oauth_enabled": True,
                "grant_type": grant_type,
                "client_id": oauth_config.get('client_id'),
                "scopes": oauth_config.get('scopes', []),
                "authorization_url": oauth_config.get('authorization_url'),
                "redirect_uri": oauth_config.get('redirect_uri'),
                "message": "Gateway configured for Authorization Code flow"
            }
        else:
            return {
                "oauth_enabled": True,
                "grant_type": grant_type,
                "client_id": oauth_config.get('client_id'),
                "scopes": oauth_config.get('scopes', []),
                "message": f"Gateway configured for {grant_type} flow"
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get OAuth status: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get OAuth status: {str(e)}"
        )


@oauth_router.post("/fetch-tools/{gateway_id}")
async def fetch_tools_after_oauth(gateway_id: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Fetch tools from MCP server after OAuth completion for Authorization Code flow."""
    try:
        from mcpgateway.services.gateway_service import GatewayService

        gateway_service = GatewayService()
        result = await gateway_service.fetch_tools_after_oauth(db, gateway_id)

        # Store the tools in the database
        # from mcpgateway.services.tool_service import ToolService
        # tool_service = ToolService()

        # # Create tools from the result
        # tools_created = []
        # for tool_data in result.get("tools", []):
        #     try:
        #         # Convert ToolCreate to dict if it's not already
        #         if hasattr(tool_data, 'model_dump'):
        #             tool_dict = tool_data.model_dump()
        #         else:
        #             tool_dict = dict(tool_data)

        #         # Add gateway_id to tool data
        #         tool_dict["gateway_id"] = gateway_id

        #         # Convert dict back to ToolCreate object for register_tool
        #         from mcpgateway.schemas import ToolCreate
        #         tool_create_obj = ToolCreate.model_validate(tool_dict)

        #         tool_created = await tool_service.register_tool(db, tool_create_obj)
        #         tools_created.append(tool_created)
        #     except Exception as e:
        #         # Get tool name safely
        #         tool_name = "unknown"
        #         if hasattr(tool_data, 'name'):
        #             tool_name = tool_data.name
        #         elif isinstance(tool_data, dict):
        #             tool_name = tool_data.get('name', 'unknown')

        #         logger.warning(f"Failed to create tool {tool_name}: {e}")


        return {
            "success": True,
            "message": f"Successfully fetched and created {len(result.get("tools", []))} tools"
        }

    except Exception as e:
        logger.error(f"Failed to fetch tools after OAuth for gateway {gateway_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch tools: {str(e)}")
