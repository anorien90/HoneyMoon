# Contributing to HoneyMoon

Thank you for your interest in contributing to HoneyMoon! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Reporting Issues](#reporting-issues)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone. Please be considerate in your interactions and contributions.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/your-username/HoneyMoon.git
   cd HoneyMoon
   ```
3. **Add the upstream remote:**
   ```bash
   git remote add upstream https://github.com/anorien90/HoneyMoon.git
   ```

## Development Setup

### Prerequisites

- Python 3.9 or higher
- Node.js (for frontend development, optional)
- Docker & Docker Compose (for testing with honeypot)
- nmap (for deep scanning features)

### Setting Up Your Environment

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest black flake8

# Run the application
python -m src.app
```

### Environment Variables

For development, you may want to set these environment variables:

```bash
export IPMAP_DEBUG=1
export IPMAP_PORT=5000
export HONEY_AUTO_INGEST=false  # Disable auto-ingest during development
```

## Making Changes

### Branching Strategy

- Create a feature branch from `main`:
  ```bash
  git checkout main
  git pull upstream main
  git checkout -b feature/your-feature-name
  ```

- Use descriptive branch names:
  - `feature/` - New features
  - `fix/` - Bug fixes
  - `docs/` - Documentation updates
  - `refactor/` - Code refactoring

### Commit Messages

Write clear and descriptive commit messages:

```
Short summary (50 chars or less)

More detailed explanatory text, if necessary. Wrap it to about 72
characters. The blank line separating the summary from the body is
critical.

- Bullet points are okay
- Use a hyphen or asterisk for bullet points
```

## Coding Standards

### Python

- Follow [PEP 8](https://pep8.org/) style guidelines
- Use type hints where appropriate
- Write docstrings for public functions and classes
- Keep functions focused and concise

Example:
```python
def get_node_from_db_or_web(self, ip: str, session=None) -> Optional[NetworkNode]:
    """
    Retrieve or create a NetworkNode for the given IP address.

    Args:
        ip: The IP address to look up
        session: Optional SQLAlchemy session (defaults to self.db)

    Returns:
        NetworkNode instance or None if lookup fails
    """
    # Implementation...
```

### JavaScript

- Use ES6+ features
- Follow consistent naming conventions (camelCase for variables/functions)
- Add JSDoc comments for functions
- Handle errors appropriately

Example:
```javascript
/**
 * Fetch data from the API with retry logic.
 * @param {string} url - The API endpoint URL
 * @param {Object} options - Request options
 * @returns {Promise<Object>} API response
 */
export async function apiGet(url, options = {}) {
    // Implementation...
}
```

### HTML/CSS

- Use semantic HTML elements
- Follow BEM naming convention for CSS classes
- Keep styles modular and reusable
- Ensure accessibility (ARIA attributes, keyboard navigation)

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_forensic_engine.py

# Run with verbose output
pytest -v

# Run with coverage
pytest --cov=src
```

### Writing Tests

- Place tests in the `tests/` directory
- Name test files `test_*.py`
- Use descriptive test function names
- Include both positive and negative test cases

Example:
```python
import pytest
from src.forensic_engine import ForensicEngine

def test_get_entry_returns_node_for_valid_ip():
    engine = ForensicEngine()
    # Add a test node
    result = engine.get_entry("8.8.8.8")
    assert result is not None
    assert result["ip"] == "8.8.8.8"

def test_get_entry_returns_none_for_unknown_ip():
    engine = ForensicEngine()
    result = engine.get_entry("0.0.0.0")
    assert result is None
```

## Submitting Changes

1. **Ensure tests pass:**
   ```bash
   pytest
   ```

2. **Format your code:**
   ```bash
   black src/
   flake8 src/
   ```

3. **Commit your changes:**
   ```bash
   git add .
   git commit -m "Add descriptive commit message"
   ```

4. **Push to your fork:**
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Create a Pull Request:**
   - Go to the original repository on GitHub
   - Click "New Pull Request"
   - Select your fork and branch
   - Fill out the PR template with:
     - Description of changes
     - Related issue numbers
     - Testing performed

### Pull Request Guidelines

- Keep PRs focused on a single change
- Update documentation if needed
- Add tests for new features
- Respond to review feedback promptly

## Reporting Issues

### Bug Reports

When reporting bugs, please include:

1. **Description** - Clear description of the issue
2. **Steps to Reproduce** - Minimal steps to reproduce the bug
3. **Expected Behavior** - What should happen
4. **Actual Behavior** - What actually happens
5. **Environment** - Python version, OS, browser (if applicable)
6. **Logs** - Relevant error messages or logs

### Feature Requests

When requesting features, please include:

1. **Use Case** - Why is this feature needed?
2. **Proposed Solution** - How should it work?
3. **Alternatives** - Other solutions you've considered

### Security Issues

**Please do not report security vulnerabilities through public issues.**

Instead, please email security concerns directly to the maintainers. Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Project Structure

```
HoneyMoon/
├── src/                       # Python source code
│   ├── app.py                 # Flask application
│   ├── entry.py               # Database models
│   ├── forensic_engine.py     # Core engine
│   ├── forensic_extension.py  # Fingerprinting helpers
│   └── honeypot_models.py     # Honeypot models
├── static/                    # Frontend assets
│   ├── app.js                 # Main JavaScript
│   ├── api.js                 # API client
│   ├── map.js                 # Map functionality
│   └── *.css                  # Stylesheets
├── templates/                 # HTML templates
├── tests/                     # Test files
├── data/                      # Data files (gitignored)
├── requirements.txt           # Python dependencies
└── docker-compose.yml         # Docker configuration
```

## Areas for Contribution

We welcome contributions in these areas:

- **Bug fixes** - Help us squash bugs
- **Documentation** - Improve guides and API docs
- **Testing** - Add test coverage
- **Performance** - Optimize queries and processing
- **UI/UX** - Enhance the web interface
- **Integrations** - Add support for more honeypots or data sources
- **Security** - Improve security practices

## Questions?

If you have questions about contributing, feel free to:

- Open a discussion on GitHub
- Comment on relevant issues
- Reach out to the maintainers

Thank you for contributing to HoneyMoon! 🌙
