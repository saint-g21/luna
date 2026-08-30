#!/usr/bin/env python3
"""
Web Search MCP Server using DuckDuckGo (free, no API key)
Provides a web_search tool for your secure CLI.
"""

import asyncio
import json
from duckduckgo_search import DDGS
from mcp.server import Server, stdio_server
from mcp.types import Tool, TextContent

# Create the MCP server
app = Server("duckduckgo-web-search")

@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="web_search",
            description="Search the web using DuckDuckGo. Returns up to 5 results with titles, snippets, and URLs.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "The search query"},
                    "max_results": {"type": "integer", "description": "Maximum results (default 5, max 10)"}
                },
                "required": ["query"]
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name != "web_search":
        return [TextContent(type="text", text=f"Unknown tool: {name}")]

    query = arguments.get("query")
    if not query:
        return [TextContent(type="text", text="Error: missing 'query' argument")]

    max_results = min(arguments.get("max_results", 5), 10)

    try:
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=max_results))
            if not results:
                return [TextContent(type="text", text=f"No results found for '{query}'")]

            output = [f"**Search results for:** {query}\n"]
            for i, r in enumerate(results, 1):
                title = r.get('title', 'No title')
                body = r.get('body', 'No description')
                href = r.get('href', '#')
                output.append(f"{i}. **{title}**")
                output.append(f"   {body[:300]}{'...' if len(body) > 300 else ''}")
                output.append(f"   🔗 {href}\n")
            return [TextContent(type="text", text="\n".join(output))]
    except Exception as e:
        return [TextContent(type="text", text=f"Search error: {str(e)}")]

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
