<div align="center">

<!-- omit in toc -->
# SecureMCP 🔒

<strong>The secure, enterprise-ready way to build MCP servers and clients.</strong>

*Built for security-first organizations*

[![Docs](https://img.shields.io/badge/docs-purecipher.com-blue)](https://purecipher.com)
[![License](https://img.shields.io/github/license/PureCipher/xsecuremcp.svg)](https://github.com/PureCipher/xsecuremcp/blob/main/LICENSE)

<a href="https://trendshift.io/repositories/PureCipher/xsecuremcp" target="_blank"><img src="https://trendshift.io/api/badge/repositories/PureCipher/xsecuremcp" alt="PureCipher%2Fxsecuremcp | Trendshift" style="width: 250px; height: 55px;" width="250" height="55"/></a>
</div>

> [!Note]
>
> #### Security-First MCP Framework
>
> SecureMCP is the enterprise-grade framework for building secure Model Context Protocol servers and clients. **Built on the foundation of [FastMCP](https://github.com/jlowin/fastmcp)** by [Prefect](https://www.prefect.io/), SecureMCP extends the excellent FastMCP framework with comprehensive security features designed for production environments.
>
> SecureMCP provides **enterprise-grade security** with features including advanced authentication, authorization, audit logging, data encryption, compliance tools, and secure deployment patterns.
>
> Ready to secure your MCP infrastructure? Follow the [installation instructions](https://purecipher.com/getting-started/installation) to get started with SecureMCP.

---

The [Model Context Protocol (MCP)](https://modelcontextprotocol.io) is a new, standardized way to provide context and tools to your LLMs, and SecureMCP makes building secure, enterprise-ready MCP servers and clients simple and intuitive. Create secure tools, expose protected resources, define authenticated prompts, and connect components with enterprise-grade security built-in.

```python
# server.py
from securemcp import SecureMCP
from securemcp.auth import JWTProvider
from securemcp.policy import RoleBasedAccess

mcp = SecureMCP("Secure Demo 🔒")

# Configure authentication
mcp.auth_provider = JWTProvider(secret_key="your-secret-key")

# Configure access control
mcp.access_control = RoleBasedAccess()

@mcp.tool(requires_auth=True, roles=["user", "admin"])
def add(a: int, b: int) -> int:
    """Add two numbers - requires authentication"""
    return a + b

if __name__ == "__main__":
    mcp.run()
```

Run the server locally:

```bash
securemcp run server.py
```

### 📚 Documentation

SecureMCP's complete documentation is available at **[purecipher.com](https://purecipher.com)**, including detailed security guides, API references, and enterprise deployment patterns. This readme provides only a high-level overview.

Documentation is also available in [llms.txt format](https://llmstxt.org/), which is a simple markdown standard that LLMs can consume easily.

There are two ways to access the LLM-friendly documentation:

- [`llms.txt`](https://purecipher.com/llms.txt) is essentially a sitemap, listing all the pages in the documentation.
- [`llms-full.txt`](https://purecipher.com/llms-full.txt) contains the entire documentation. Note this may exceed the context window of your LLM.

---

<!-- omit in toc -->
## Table of Contents

- [What is MCP?](#what-is-mcp)
- [Why SecureMCP?](#why-securemcp)
- [Security Features](#security-features)
- [Credits](#credits)
- [Installation](#installation)
- [Core Concepts](#core-concepts)
  - [The `SecureMCP` Server](#the-securemcp-server)
  - [Tools](#tools)
  - [Resources \& Templates](#resources--templates)
  - [Prompts](#prompts)
  - [Context](#context)
  - [MCP Clients](#mcp-clients)
- [Advanced Features](#advanced-features)
  - [Proxy Servers](#proxy-servers)
  - [Composing MCP Servers](#composing-mcp-servers)
  - [OpenAPI \& FastAPI Generation](#openapi--fastapi-generation)
  - [Authentication \& Security](#authentication--security)
- [Running Your Server](#running-your-server)
- [Contributing](#contributing)
  - [Prerequisites](#prerequisites)
  - [Setup](#setup)
  - [Unit Tests](#unit-tests)
  - [Static Checks](#static-checks)
  - [Pull Requests](#pull-requests)

---

## What is MCP?

The [Model Context Protocol (MCP)](https://modelcontextprotocol.io) lets you build servers that expose data and functionality to LLM applications in a secure, standardized way. It is often described as "the USB-C port for AI", providing a uniform way to connect LLMs to resources they can use. It may be easier to think of it as an API, but specifically designed for LLM interactions. MCP servers can:

- Expose data through **Resources** (think of these sort of like GET endpoints; they are used to load information into the LLM's context)
- Provide functionality through **Tools** (sort of like POST endpoints; they are used to execute code or otherwise produce a side effect)
- Define interaction patterns through **Prompts** (reusable templates for LLM interactions)
- And more!

SecureMCP provides a high-level, Pythonic interface for building, managing, and interacting with these servers with enterprise-grade security.

## Why SecureMCP?

The MCP protocol is powerful but implementing it securely in enterprise environments involves complex security considerations - authentication, authorization, audit logging, data encryption, compliance requirements, and secure deployment patterns. SecureMCP handles all the security complexities and enterprise requirements, so you can focus on building secure tools that meet compliance standards.

**SecureMCP extends [FastMCP](https://github.com/jlowin/fastmcp)** - the excellent, fast, and Pythonic MCP framework by [Prefect](https://www.prefect.io/) - with comprehensive enterprise-grade security features. While FastMCP provides outstanding server-building capabilities and developer experience, SecureMCP adds a complete security-focused ecosystem including advanced authentication systems, role-based access control, audit logging, data encryption, compliance tools, and secure deployment patterns.

SecureMCP aims to be:

🔒 **Secure:** Enterprise-grade security built-in from the ground up

🛡️ **Compliant:** Meets SOC2, HIPAA, and other compliance requirements

🏢 **Enterprise-Ready:** Designed for production environments with strict security needs

🔍 **Auditable:** Comprehensive logging and monitoring for security compliance

## Security Features

SecureMCP provides comprehensive security features designed for enterprise environments:

### 🔐 Authentication & Authorization
- **Multiple Auth Providers**: JWT, OAuth2, SAML, LDAP, and custom authentication
- **Role-Based Access Control**: Fine-grained permissions and role management
- **Multi-Factor Authentication**: Support for MFA and 2FA
- **Session Management**: Secure session handling with configurable timeouts

### 🛡️ Data Protection
- **End-to-End Encryption**: TLS/SSL encryption for all communications
- **Data Encryption at Rest**: Encrypt sensitive data stored by the server
- **Input Validation**: Comprehensive input sanitization and validation
- **Output Filtering**: Prevent data leakage through response filtering

### 📊 Compliance & Auditing
- **Audit Logging**: Comprehensive logging of all operations and access
- **Compliance Frameworks**: Built-in support for SOC2, HIPAA, GDPR, and more
- **Security Monitoring**: Real-time security event monitoring and alerting
- **Data Retention**: Configurable data retention policies

### 🚀 Secure Deployment
- **Container Security**: Secure container deployment with minimal attack surface
- **Network Security**: Configurable network policies and firewall rules
- **Secret Management**: Secure handling of API keys, certificates, and secrets
- **Health Checks**: Security-focused health monitoring and reporting

## Credits

SecureMCP is built on the solid foundation of **[FastMCP](https://github.com/jlowin/fastmcp)** by [Prefect](https://www.prefect.io/). We extend our sincere gratitude to the FastMCP team for creating an excellent, fast, and Pythonic framework for building MCP servers and clients.

**FastMCP** provides:
- High-level, Pythonic interface for MCP development
- Comprehensive tool, resource, and prompt management
- Multiple transport protocols (STDIO, HTTP, SSE)
- Client libraries and testing frameworks
- OpenAPI and FastAPI integration
- And much more!

SecureMCP adds enterprise-grade security features on top of this excellent foundation, making it suitable for production environments with strict security and compliance requirements.

## Installation

We recommend installing SecureMCP with [uv](https://docs.astral.sh/uv/):

```bash
uv pip install securemcp
```

For full installation instructions, including verification, upgrading from [FastMCP](https://github.com/jlowin/fastmcp), and enterprise setup, see the [**Installation Guide**](https://purecipher.com/getting-started/installation).

## Core Concepts

These are the building blocks for creating secure MCP servers and clients with SecureMCP.

### The `SecureMCP` Server

The central object representing your secure MCP application. It holds your tools, resources, and prompts, manages connections, and includes built-in security features like authentication, authorization, and audit logging.

```python
from securemcp import SecureMCP
from securemcp.auth import JWTProvider

# Create a secure server instance
mcp = SecureMCP(name="MySecureAssistant")
mcp.auth_provider = JWTProvider(secret_key="your-secret-key")
```

Learn more in the [**SecureMCP Server Documentation**](https://purecipher.com/servers/securemcp).

### Tools

Tools allow LLMs to perform actions by executing your Python functions (sync or async). Ideal for computations, API calls, or side effects (like `POST`/`PUT`). SecureMCP handles schema generation from type hints and docstrings, plus adds security controls like authentication requirements and role-based access control. Tools can return various types, including text, JSON-serializable objects, and even images or audio aided by the SecureMCP media helper classes.

```python
@mcp.tool(requires_auth=True, roles=["admin"], audit_log=True)
def multiply(a: float, b: float) -> float:
    """Multiplies two numbers - requires admin role and logs access."""
    return a * b
```

Learn more in the [**Tools Documentation**](https://purecipher.com/servers/tools).

### Resources & Templates

Resources expose read-only data sources (like `GET` requests). Use `@mcp.resource("your://uri")`. Use `{placeholders}` in the URI to create dynamic templates that accept parameters, allowing clients to request specific data subsets. SecureMCP adds access control and data encryption to protect sensitive resources.

```python
# Static resource with access control
@mcp.resource("config://version", requires_auth=True)
def get_version(): 
    return "2.0.1"

# Dynamic resource template with role-based access
@mcp.resource("users://{user_id}/profile", roles=["admin", "user"])
def get_profile(user_id: int):
    # Fetch profile for user_id with access control...
    return {"name": f"User {user_id}", "status": "active"}
```

Learn more in the [**Resources & Templates Documentation**](https://purecipher.com/servers/resources).

### Prompts

Prompts define reusable message templates to guide LLM interactions. Decorate functions with `@mcp.prompt`. Return strings or `Message` objects. SecureMCP adds authentication requirements and content filtering to protect prompt templates.

```python
@mcp.prompt(requires_auth=True, roles=["user"])
def summarize_request(text: str) -> str:
    """Generate a prompt asking for a summary - requires authentication."""
    return f"Please summarize the following text:\n\n{text}"
```

Learn more in the [**Prompts Documentation**](https://purecipher.com/servers/prompts).

### Context

Access MCP session capabilities within your tools, resources, or prompts by adding a `ctx: Context` parameter. Context provides methods for:

- **Logging:** Log messages to MCP clients with `ctx.info()`, `ctx.error()`, etc.
- **LLM Sampling:** Use `ctx.sample()` to request completions from the client's LLM.
- **HTTP Request:** Use `ctx.http_request()` to make HTTP requests to other servers.
- **Resource Access:** Use `ctx.read_resource()` to access resources on the server
- **Progress Reporting:** Use `ctx.report_progress()` to report progress to the client.
- **Security Context:** Access user identity, roles, and audit logging with `ctx.user`, `ctx.roles`, `ctx.audit_log()`
- and more...

To access the context, add a parameter annotated as `Context` to any mcp-decorated function. SecureMCP will automatically inject the correct context object when the function is called.

```python
from securemcp import SecureMCP, Context

mcp = SecureMCP("My Secure MCP Server")

@mcp.tool(requires_auth=True)
async def process_data(uri: str, ctx: Context):
    # Log a message to the client
    await ctx.info(f"Processing {uri} for user {ctx.user.id}...")

    # Read a resource from the server
    data = await ctx.read_resource(uri)

    # Ask client LLM to summarize the data
    summary = await ctx.sample(f"Summarize: {data.content[:500]}")

    # Log the access for audit purposes
    await ctx.audit_log("data_processed", {"uri": uri, "user": ctx.user.id})

    # Return the summary
    return summary.text
```

Learn more in the [**Context Documentation**](https://purecipher.com/servers/context).

### MCP Clients

Interact with *any* MCP server programmatically using the `securemcp.Client`. It supports various transports (Stdio, SSE, In-Memory) and often auto-detects the correct one. The client includes built-in authentication support and can handle advanced patterns like server-initiated **LLM sampling requests** if you provide an appropriate handler.

Critically, the client allows for efficient **in-memory testing** of your servers by connecting directly to a `SecureMCP` server instance via the `SecureMCPTransport`, eliminating the need for process management or network calls during tests.

```python
from securemcp import Client
from securemcp.auth import BearerAuth

async def main():
    # Connect with authentication
    auth = BearerAuth(token="your-jwt-token")
    async with Client("my_secure_server.py", auth=auth) as client:
        tools = await client.list_tools()
        print(f"Available tools: {tools}")
        result = await client.call_tool("add", {"a": 5, "b": 3})
        print(f"Result: {result.text}")

    # Connect via SSE with authentication
    async with Client("https://secure-server.com/sse", auth=auth) as client:
        # ... use the client
        pass
```

To use clients to test servers, use the following pattern:

```python
from securemcp import SecureMCP, Client

mcp = SecureMCP("My Secure MCP Server")

async def main():
    # Connect via in-memory transport
    async with Client(mcp) as client:
        # ... use the client
```

SecureMCP also supports connecting to multiple servers through a single unified client using the standard MCP configuration format with authentication:

```python
from securemcp import Client
from securemcp.auth import BearerAuth

# Standard MCP configuration with multiple servers and auth
config = {
    "mcpServers": {
        "weather": {
            "url": "https://weather-api.example.com/mcp",
            "auth": {"type": "bearer", "token": "weather-token"}
        },
        "assistant": {
            "command": "python", 
            "args": ["./assistant_server.py"],
            "auth": {"type": "jwt", "secret": "assistant-secret"}
        }
    }
}

# Create a client that connects to all servers
client = Client(config)

async def main():
    async with client:
        # Access tools and resources with server prefixes
        forecast = await client.call_tool("weather_get_forecast", {"city": "London"})
        answer = await client.call_tool("assistant_answer_question", {"query": "What is MCP?"})
```

Learn more in the [**Client Documentation**](https://purecipher.com/clients/client) and [**Transports Documentation**](https://purecipher.com/clients/transports).

## Advanced Features

SecureMCP introduces powerful ways to structure and deploy your secure MCP applications with enterprise-grade security.

### Proxy Servers

Create a SecureMCP server that acts as an intermediary for another local or remote MCP server using `SecureMCP.as_proxy()`. This is especially useful for bridging transports (e.g., remote SSE to local Stdio) or adding a security layer to a server you don't control.

Learn more in the [**Proxying Documentation**](https://purecipher.com/patterns/proxy).

### Composing MCP Servers

Build modular applications by mounting multiple `SecureMCP` instances onto a parent server using `mcp.mount()` (live link) or `mcp.import_server()` (static copy). Each mounted server maintains its own security policies and access controls.

Learn more in the [**Composition Documentation**](https://purecipher.com/patterns/composition).

### OpenAPI & FastAPI Generation

Automatically generate SecureMCP servers from existing OpenAPI specifications (`SecureMCP.from_openapi()`) or FastAPI applications (`SecureMCP.from_fastapi()`), instantly bringing your web APIs to the MCP ecosystem with built-in security controls.

Learn more: [**OpenAPI Integration**](https://purecipher.com/integrations/openapi) | [**FastAPI Integration**](https://purecipher.com/integrations/fastapi).

### Authentication & Security

SecureMCP provides comprehensive enterprise-grade security features to secure both your MCP servers and clients in production environments. Protect your server endpoints from unauthorized access and authenticate your clients against secured MCP servers using industry-standard protocols.

- **Advanced Authentication**: JWT, OAuth2, SAML, and custom authentication providers
- **Role-Based Access Control**: Fine-grained permissions and role management
- **Audit Logging**: Comprehensive logging for compliance and security monitoring
- **Data Encryption**: End-to-end encryption for sensitive data
- **Compliance Tools**: Built-in support for SOC2, HIPAA, and other compliance requirements
- **Security Policies**: Configurable security policies and access controls

Learn more in the **Authentication Documentation** for [servers](https://purecipher.com/servers/auth) and [clients](https://purecipher.com/clients/auth).

## Running Your Server

The main way to run a SecureMCP server is by calling the `run()` method on your server instance:

```python
# server.py
from securemcp import SecureMCP
from securemcp.auth import JWTProvider

mcp = SecureMCP("Secure Demo 🔒")
mcp.auth_provider = JWTProvider(secret_key="your-secret-key")

@mcp.tool(requires_auth=True)
def hello(name: str) -> str:
    return f"Hello, {name}!"

if __name__ == "__main__":
    mcp.run()  # Default: uses STDIO transport
```

SecureMCP supports three transport protocols with built-in security:

**STDIO (Default)**: Best for local tools and command-line scripts.

```python
mcp.run(transport="stdio")  # Default, so transport argument is optional
```

**Streamable HTTP**: Recommended for web deployments with TLS encryption.

```python
mcp.run(transport="http", host="127.0.0.1", port=8000, path="/mcp", tls_cert="cert.pem", tls_key="key.pem")
```

**SSE**: For compatibility with existing SSE clients with authentication.

```python
mcp.run(transport="sse", host="127.0.0.1", port=8000, require_auth=True)
```

See the [**Running Server Documentation**](https://purecipher.com/deployment/running-server) for more details.

## Contributing

Contributions are the core of open source! We welcome improvements and security enhancements.

### Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (Recommended for environment management)

### Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/PureCipher/xsecuremcp.git 
   cd xsecuremcp
   ```

2. Create and sync the environment:

   ```bash
   uv sync
   ```

   This installs all dependencies, including dev tools.

3. Activate the virtual environment (e.g., `source .venv/bin/activate` or via your IDE).

### Unit Tests

SecureMCP has a comprehensive unit test suite including security tests. All PRs must introduce or update tests as appropriate and pass the full suite.

Run tests using pytest:

```bash
pytest
```

or if you want an overview of the code coverage

```bash
uv run pytest --cov=src --cov=examples --cov-report=html
```

### Static Checks

SecureMCP uses `pre-commit` for code formatting, linting, and type-checking. All PRs must pass these checks (they run automatically in CI).

Install the hooks locally:

```bash
uv run pre-commit install
```

The hooks will now run automatically on `git commit`. You can also run them manually at any time:

```bash
pre-commit run --all-files
# or via uv
uv run pre-commit run --all-files
```

### Pull Requests

1. Fork the repository on GitHub.
2. Create a feature branch from `main`.
3. Make your changes, including tests and documentation updates.
4. Ensure tests and pre-commit hooks pass.
5. Commit your changes and push to your fork.
6. Open a pull request against the `main` branch of `PureCipher/xsecuremcp`.

Please open an issue or discussion for questions or suggestions before starting significant work!
