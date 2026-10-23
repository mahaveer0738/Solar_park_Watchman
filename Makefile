# Solar Park Watchman - Makefile
.PHONY: all up attacks evaluate demo down test

PYTHON := python

all: evaluate

up:
	$(PYTHON) make.py up

attacks:
	$(PYTHON) make.py attacks

evaluate:
	$(PYTHON) make.py evaluate

demo:
	$(PYTHON) make.py demo

down:
	$(PYTHON) make.py down

test:
	$(PYTHON) -m pytest tests/ -v
