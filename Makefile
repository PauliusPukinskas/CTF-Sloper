.PHONY: run install full-install doctor doctor-json inventory inventory-json flags flags-json check test clean package

TARGET ?= projects

run:
	bash START_HERE.sh

install:
	pip install -r requirements.txt

full-install:
	bash FULL_INSTALL.sh

doctor:
	python3 scripts/doctor.py

doctor-json:
	python3 scripts/doctor.py --json

inventory:
	python3 scripts/artifact_inventory.py "$(TARGET)"

inventory-json:
	python3 scripts/artifact_inventory.py --json "$(TARGET)"

flags:
	python3 scripts/flag_hunter.py "$(TARGET)"

flags-json:
	python3 scripts/flag_hunter.py --json "$(TARGET)"

check:
	bash scripts/check.sh

test:
	python3 -m pytest -q

clean:
	rm -rf .pytest_cache __pycache__ sloper_v72/__pycache__

package:
	bash scripts/package_release.sh
