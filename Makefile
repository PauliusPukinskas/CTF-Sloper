.PHONY: run install full-install check test clean package

run:
	bash START_HERE.sh

install:
	pip install -r requirements.txt

full-install:
	bash FULL_INSTALL.sh

check:
	bash scripts/check.sh

test:
	python3 -m pytest -q

clean:
	rm -rf .pytest_cache __pycache__ sloper_v72/__pycache__

package:
	bash scripts/package_release.sh
