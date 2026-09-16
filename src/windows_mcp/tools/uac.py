"""UAC handling tool — WaitForUACPrompt.

Lets the agent block until a UAC consent prompt fires on the Secure Desktop,
returning the dialog's UIA tree and (best-effort) verified publisher so the
agent can decide whether to approve it.

Requires the LocalSystem host service to be installed
(``uv run windows-mcp service secure-desktop install``). Without the service,
this tool raises rather than silently blocking — the broker cannot see the
Secure Desktop on its own.

Failures raise ``ToolError`` so FastMCP sets ``isError=true`` on the wire.
A timeout raises ``TimeoutError``, matching the ``WaitFor`` tool, which also
raises when its condition never holds.
"""

from __future__ import annotations

from typing import Annotated

from fastmcp import Context
from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from windows_mcp.infrastructure import with_analytics


def register(mcp, *, get_desktop, get_analytics):
    @mcp.tool(
        name="WaitForUACPrompt",
        description=(
            "Block until a UAC consent prompt appears on the Secure Desktop, then "
            "return the dialog as a UIA tree plus the verified publisher (if "
            "detectable). Use this when you have just triggered an operation that "
            "is expected to require elevation. Requires the Windows-MCP host "
            "service to be installed."
        ),
        annotations=ToolAnnotations(
            title="WaitForUACPrompt",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=False,
            openWorldHint=False,
        ),
    )
    @with_analytics(get_analytics(), "WaitForUACPrompt-Tool")
    def wait_for_uac_prompt(
        timeout_ms: Annotated[
            int,
            Field(
                description=(
                    "Maximum time to wait, in milliseconds, before giving up. "
                    "Defaults to 60000 (60 seconds)."
                ),
                ge=100,
                le=600_000,
            ),
        ] = 60_000,
        ctx: Context = None,
    ) -> dict:
        from windows_mcp.service import get_host_client

        client = get_host_client()
        if not client.is_available():
            raise ToolError(
                "Windows-MCP Secure Desktop host service is not installed or not "
                "running. Install it with: "
                "`uv run windows-mcp service secure-desktop install` "
                "(requires Administrator)."
            )
        try:
            result = client.wait_for_uac_prompt(timeout_ms=timeout_ms)
        except Exception as exc:
            raise ToolError(f"Host service call failed: {exc}") from exc
        if result is None:
            raise TimeoutError(
                f"Timed out after {timeout_ms / 1000:.2f}s waiting for a UAC consent "
                "prompt: none appeared. The operation may not have required elevation."
            )
        try:
            pol = client.policy_state()
        except Exception:
            pol = None
        return {
            "ok": True,
            "fired": True,
            "desktop": result.get("desktop"),
            "publisher": result.get("publisher"),
            "tree": result.get("tree"),
            "policy": pol,
        }
