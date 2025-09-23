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
> Ready to secure your MCP infrastructure? Follow the [installation instructions](https://purecipher.com) to get started with SecureMCP.

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

- [`llms.txt`](https://purecipher.com) is essentially a sitemap, listing all the pages in the documentation.
- [`llms-full.txt`](https://purecipher.com) contains the entire documentation. Note this may exceed the context window of your LLM.

---

<!-- omit in toc -->
## Table of Contents

- [What is MCP?](#what-is-mcp)
- [Why SecureMCP?](#why-securemcp)
- [Security Features](#security-features)
- [Credits](#credits)
- [Contributing](#contributing)

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

## Contributing

Contributions are the core of open source! We welcome improvements and security enhancements.

### Pull Requests

1. Fork the repository on GitHub.
2. Create a feature branch from `main`.
3. Make your changes, including tests and documentation updates.
4. Ensure tests and pre-commit hooks pass.
5. Commit your changes and push to your fork.
6. Open a pull request against the `main` branch of `PureCipher/xsecuremcp`.

Please open an issue or discussion for questions or suggestions before starting significant work!
