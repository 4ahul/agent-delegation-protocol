.PHONY: test run demo build docker

test:
	pytest

run:
	uvicorn server.app:app --reload --port 8000

demo:
	python examples/end_to_end.py

build:
	python -m build

docker:
	docker compose up --build
