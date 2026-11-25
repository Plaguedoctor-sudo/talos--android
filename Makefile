.PHONY: all check test test-trust test-mobile fixture verify verify-strict build-daemons clean reproducible reproducible-verify reproducible-docker reuse-lint hardware-matrix-check hardware-matrix-render

PYTHON ?= python3
PYTHONPATH := $(CURDIR)/.deps:$(CURDIR):$(PYTHONPATH)
export PYTHONPATH

all: check

fixture:
	$(PYTHON) tests/argx/make_fixture.py

test-trust: fixture
	$(PYTHON) -m pytest tests/argx/test_tamper.py tests/tag/test_tags.py tests/producers/test_producers.py tests/producers/test_ledger.py tests/producers/test_degraded.py tests/e2e/test_roundtrip.py tests/e2e/test_range.py tests/e2e/test_multiboot.py tests/verify/test_grade.py -v

test-mobile:
	@chmod +x mobile/test/*.sh
	./mobile/test/run-all-tests.sh

build-daemons:
	gcc -O2 -Wall mobile/telephony/lrd-telephonyd.c -o mobile/telephony/lrd-telephonyd -lpthread
	gcc -O2 -Wall mobile/telephony/lrd-telephony.c -o mobile/telephony/lrd-telephony
	gcc -O2 -Wall mobile/sensors/lrd-sensord.c -o mobile/sensors/lrd-sensord -lpthread -lm
	gcc -O2 -Wall mobile/power/lrd-wakelockd.c -o mobile/power/lrd-wakelockd -lpthread
	gcc -O2 -Wall mobile/bluetooth/lrd-bluetoothd.c -o mobile/bluetooth/lrd-bluetoothd
	gcc -O2 -Wall mobile/bluetooth/lrd-bluetooth.c -o mobile/bluetooth/lrd-bluetooth
	gcc -O2 -Wall mobile/wifi/lrd-wifid.c -o mobile/wifi/lrd-wifid
	gcc -O2 -Wall mobile/wifi/lrd-wifi.c -o mobile/wifi/lrd-wifi
	gcc -O2 -Wall mobile/firewall/lrd-firewalld.c -o mobile/firewall/lrd-firewalld
	gcc -O2 -Wall mobile/firewall/lrd-firewall.c -o mobile/firewall/lrd-firewall

test: test-trust test-mobile

verify: fixture
	$(PYTHON) -m argus.verify.cli tests/argx/fixtures/basic.argx --keyring tests/argx/fixtures/keyring --scope-check || [ $$? -eq 1 ]

verify-strict: fixture
	$(PYTHON) -m argus.verify.cli tests/argx/fixtures/basic.argx --keyring tests/argx/fixtures/keyring --scope-check --strict || [ $$? -eq 2 ]

check: test-trust test-mobile verify-strict
	@echo "========================================================================"
	@echo "✔ ALL SOVEREIGN MOBILE OS SUBSYSTEMS & TRUST GATES VERIFIED SUCCESSFULLY."
	@echo "========================================================================"

clean:
	rm -rf .pytest_cache tests/argx/__pycache__ tests/tag/__pycache__ argus/__pycache__ argus/*/__pycache__ out

reproducible:
	@chmod +x scripts/repro-build.sh scripts/repro-attest.sh repro/verify-attestation.py
	./scripts/repro-attest.sh

ATTESTATION ?= $(firstword $(wildcard repro/attestation-*.json))
BUILD_DIR ?= out/a

reproducible-verify:
	@if [ -z "$(ATTESTATION)" ]; then \
		echo "Error: No attestation specified. Usage: make reproducible-verify ATTESTATION=repro/attestation-<sha>.json BUILD_DIR=out/a"; \
		exit 1; \
	fi
	$(PYTHON) repro/verify-attestation.py $(ATTESTATION) $(BUILD_DIR)

reproducible-docker:
	docker build -f repro/Dockerfile -t talos-repro:latest .

reuse-lint:
	$(PYTHON) scripts/reuse-lint.py

hardware-matrix-check:
	$(PYTHON) scripts/hardware-matrix.py --check

hardware-matrix-render:
	$(PYTHON) scripts/hardware-matrix.py --render
