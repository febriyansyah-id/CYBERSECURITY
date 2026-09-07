.PHONY: setup test lint clean

setup:
	pip install -r requirements.txt

test:
	python -m pytest tests/ -v

lint:
	ruff check . --ignore E501 || true

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
