.PHONY: validate-package

validate-package:
	uv run python devtools/validate_package.py
