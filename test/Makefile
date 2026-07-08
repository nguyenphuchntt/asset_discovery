.PHONY: test

# Packages whose internal/* source is tested via ./test/<name>/.
# Format: "test-dir:internal-pkg"
PKGS := \
	analyzer:analyzer \
	asset:asset \
	capture:capture \
	config:config \
	lifecycle:lifecycle \
	oui:oui \
	persist:persist \
	pipeline:pipeline \
	storage:storage

test:
	@cd .. && \
	pass=0; fail=0; \
	for pair in $(PKGS); do \
	  dir=$${pair%%:*}; pkg=$${pair##*:}; \
	  echo "──▶ $$dir"; \
	  out=$$(go test ./test/$$dir/ -count=1 -coverpkg=./internal/$$pkg/ -cover 2>&1); \
	  if echo "$$out" | grep -q "^ok"; then \
	    pass=$$((pass+1)); \
	    cov=$$(echo "$$out" | grep "coverage:" | awk '{print $$2}'); \
	    echo "  $$out" | tail -1 | sed 's/^/  /'; \
	  else \
	    fail=$$((fail+1)); \
	    echo "$$out"; \
	  fi; \
	done; \
	echo ""; \
	echo "━━━ Test Summary ━━━━━━━━━━━━━━━━━━━━━━━━"; \
	echo "  Passed: $$pass"; \
	echo "  Failed: $$fail"; \
	if [ $$fail -eq 0 ]; then echo "  Status:  ALL PASSED"; else echo "  Status:  FAILURES"; fi; \
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; \
	exit $$fail
