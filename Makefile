.PHONY: all check test test-trust test-mobile test-attestation fixture verify verify-strict build-daemons clean reproducible reproducible-verify reproducible-docker reuse-lint key-guard hardware-matrix-check hardware-matrix-render telephony-matrix-check telephony-matrix-render audit-prep store-index store-verify store-score-test fuzz fuzz-run fuzz-smoke

PYTHON ?= python3
PYTHONPATH := $(CURDIR)/.deps:$(CURDIR):$(PYTHONPATH)
export PYTHONPATH

all: check

fixture:
	@if [ ! -d tests/argx/fixtures/basic.argx ]; then $(PYTHON) tests/argx/make_fixture.py; fi

test-trust: fixture
	$(PYTHON) -m pytest tests/argx/test_tamper.py tests/tag/test_tags.py tests/producers/test_producers.py tests/producers/test_ledger.py tests/producers/test_degraded.py tests/e2e/test_roundtrip.py tests/e2e/test_range.py tests/e2e/test_multiboot.py tests/verify/test_grade.py -v

test-mobile:
	@chmod +x mobile/test/*.sh
	./mobile/test/run-all-tests.sh

test-attestation:
	$(PYTHON) -m pytest tests/test_rats_verifier.py -v

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

key-guard:
	bash scripts/key-guard.sh

hardware-matrix-check:
	$(PYTHON) scripts/hardware-matrix.py --check

hardware-matrix-render:
	$(PYTHON) scripts/hardware-matrix.py --render

telephony-matrix-check:
	$(PYTHON) scripts/telephony-matrix.py --check

telephony-matrix-render:
	$(PYTHON) scripts/telephony-matrix.py --render

audit-prep:
	@mkdir -p audit/test-vectors
	$(PYTHON) scripts/generate-audit-vectors.py
	$(PYTHON) -m pytest tests/ --cov=argus --cov-report=term | tee audit/coverage-report.txt
	@chmod +x scripts/check-audit-coverage.py
	@$(PYTHON) scripts/check-audit-coverage.py audit/coverage-report.txt

store-index:
	@chmod +x store/build-index.sh
	./store/build-index.sh

store-verify:
	@chmod +x store/verify-index.sh
	./store/verify-index.sh

store-score-test:
	$(PYTHON) -m pytest tests/test_store_scoring.py -v

FUZZ_TARGETS := fuzz_telephony_ril fuzz_nft_policy fuzz_argf2 fuzz_pif_json fuzz_battery_sysfs
FUZZ_DIR := fuzz
FUZZ_OUT := out/fuzz
CLANG := $(shell which clang 2>/dev/null)

fuzz:
	@mkdir -p $(FUZZ_OUT)
	@if [ -n "$(CLANG)" ]; then \
		echo "[fuzz] Compiling with Clang libFuzzer..."; \
		for t in $(FUZZ_TARGETS); do \
			clang -O1 -g -fsanitize=fuzzer,address,undefined -I. $(FUZZ_DIR)/$$t.c -o $(FUZZ_OUT)/$$t; \
		done; \
	else \
		echo "[fuzz] Clang not found; compiling with GCC + ASAN + UBSAN standalone driver..."; \
		for t in $(FUZZ_TARGETS); do \
			gcc -O1 -g -fsanitize=address,undefined -DSTANDALONE_FUZZ_DRIVER -I. $(FUZZ_DIR)/$$t.c $(FUZZ_DIR)/standalone_driver.c -o $(FUZZ_OUT)/$$t; \
		done; \
	fi
	@echo "✔ All fuzz harnesses compiled in $(FUZZ_OUT)."

fuzz-run:
	@if [ -z "$(TARGET)" ]; then \
		echo "Usage: make fuzz-run TARGET=fuzz_telephony_ril [DURATION=60]"; \
		exit 1; \
	fi
	@if [ ! -f "$(FUZZ_OUT)/$(TARGET)" ]; then \
		$(MAKE) fuzz; \
	fi
	@mkdir -p $(FUZZ_DIR)/corpus/$$(echo $(TARGET) | sed 's/^fuzz_//')
	@DURATION=$${DURATION:-60}; \
	echo "[fuzz-run] Running $(TARGET) for $${DURATION}s..."; \
	$(FUZZ_OUT)/$(TARGET) -max_total_time=$${DURATION} $(FUZZ_DIR)/corpus/$$(echo $(TARGET) | sed 's/^fuzz_//')

fuzz-smoke: fuzz
	@chmod +x scripts/fuzz-smoke.sh
	./scripts/fuzz-smoke.sh
