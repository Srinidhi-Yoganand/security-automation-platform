# Contributing to Security Automation Platform

Thank you for your interest in contributing! This document provides guidelines for contributing to this project.

## 🚀 Getting Started

1. **Fork the repository**
2. **Clone your fork**
   ```bash
   git clone https://github.com/your-username/security-automation-platform.git
   cd security-automation-platform
   ```
3. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

## 🛠️ Development Setup

### Prerequisites
- Docker & Docker Compose
- Python 3.10+
- Java 17+ (for testing)

### Setup
```bash
cd correlation-engine
pip install -r requirements.txt
```

### Run Tests
```bash
# Unit tests
python -m pytest tests/ -v

# Integration tests
python -m pytest test_end_to_end.py -v

# Full E2E test
./run-e2e-test.sh
```

## 📝 Pull Request Process

1. **Update documentation** if you're changing functionality
2. **Add tests** for new features
3. **Ensure all tests pass**
4. **Update CHANGELOG.md** with your changes
5. **Create descriptive PR title**: `feat: add XYZ` or `fix: resolve ABC`
6. **Link related issues** in PR description

## 🎯 Code Style

- **Python**: Follow PEP 8
- **Commits**: Use [Conventional Commits](https://www.conventionalcommits.org/)
  - `feat:` - New feature
  - `fix:` - Bug fix
  - `docs:` - Documentation
  - `test:` - Testing
  - `refactor:` - Code refactoring

## 🐛 Reporting Bugs

Create an issue with:
- Clear title
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Docker version, etc.)

## 💡 Feature Requests

Open an issue tagged `enhancement` with:
- Use case description
- Proposed solution
- Alternative approaches considered

## 🔒 Security Issues

**Do NOT open public issues for security vulnerabilities.**

Email security concerns to: [your-email@example.com]

## 📚 Documentation

- Update relevant `.md` files in `docs/`
- Add examples for new features
- Keep API documentation in sync

## 🧪 Testing Guidelines

- Write tests for new features
- Maintain >80% code coverage
- Test edge cases
- Include both positive and negative tests

## ✅ Code Review

- Be respectful and constructive
- Focus on code quality and maintainability
- Test locally before approving

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Questions?** Open a discussion or reach out to maintainers.
