.PHONY: setup run web test test-backend test-frontend build lint clean

setup:
	npm run setup

run:
	npm start

web:
	npm run web

test:
	npm test

test-backend:
	npm run test:backend

test-frontend:
	npm run test:frontend

build:
	npm run build

lint:
	npm run lint

clean:
	find . -type d \( -name __pycache__ -o -name .pytest_cache -o -name .mypy_cache \) -prune -exec rm -rf {} +

help:
	@echo "Targets: setup, run, web, test, test-backend, test-frontend, build, lint, clean"
