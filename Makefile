.PHONY: install-local validate-package

install-local:
	uv tool install --reinstall .

validate-package:
	uv run python devtools/validate_package.py
