# Security Policy

**⚠️ PROPRIETARY SOFTWARE - RESTRICTED ACCESS**

This security policy applies to authorized users only. Unauthorized access, use, or security testing is **STRICTLY PROHIBITED** and may result in legal action.

## Supported Versions

We currently support the following versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**⚠️ AUTHORIZED PERSONNEL ONLY**

Security vulnerability reporting is **RESTRICTED** to:
- Licensed users of this software
- Authorized security researchers with written agreement
- Contracted security auditors

### For Authorized Reporters

- **Report privately** via encrypted email only
- **Provide detailed information** about the vulnerability  
- **Do NOT exploit** or demonstrate vulnerabilities
- **Follow our NDA requirements**

### Unauthorized Security Testing

**🚫 PROHIBITED ACTIVITIES:**
- Penetration testing without authorization
- Vulnerability scanning or probing
- Security research without explicit permission
- Public disclosure of any security issues

**Unauthorized security testing will result in immediate legal action including criminal prosecution.**

## What to Include

When reporting a security vulnerability, please include:

- **Description** of the vulnerability
- **Steps to reproduce** the issue
- **Potential impact** of the vulnerability
- **Suggested fix** (if you have one)
- **Your contact information** for follow-up

## Response Timeline

- **Initial Response**: Within 48 hours of report
- **Investigation**: Within 1 week
- **Fix Development**: Timeline depends on severity
- **Public Disclosure**: After fix is deployed and verified

## Security Best Practices

### For Users

- **Keep your installation updated** to the latest version
- **Use strong API keys** and rotate them regularly
- **Don't commit sensitive data** (.env files, API keys) to version control
- **Use HTTPS** in production environments
- **Implement proper access controls** for admin functions

### For Developers

- **Validate all inputs** from users and external APIs
- **Use environment variables** for sensitive configuration
- **Implement proper authentication** and authorization
- **Follow secure coding practices**
- **Keep dependencies updated**

## Known Security Considerations

### Medical Data

- This application processes medical information
- **Do not use for actual medical diagnosis** - for educational purposes only
- **Ensure compliance** with local healthcare data regulations (HIPAA, GDPR, etc.)
- **Implement proper data handling** if deploying in healthcare settings

### API Security

- **Gemini API key** must be kept secure
- **Rate limiting** should be implemented in production
- **Input validation** is critical for AI prompts

### Web Application Security

- **CSRF protection** is enabled
- **JWT tokens** have expiration times
- **Password hashing** uses bcrypt
- **SQL injection** protection through parameterized queries

## Contact

For security concerns, please contact:

- Email: [security@medikalai.com](mailto:security@medikalai.com)
- GitHub: Open a private vulnerability report

## Acknowledgments

We appreciate the security research community and will acknowledge researchers who responsibly disclose vulnerabilities to us. 