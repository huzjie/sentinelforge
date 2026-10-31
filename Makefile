.PHONY: doctor bench test scan install

install:
	pip install -e .

doctor:
	python -m sentinelforge doctor

bench:
	python -m sentinelforge bench

test:
	python -m unittest discover -s tests -t .

scan:
	python -m sentinelforge scan examples
