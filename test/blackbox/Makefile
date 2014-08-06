ALL:=$(wildcard test-*.sh)
TESTS:=$(ALL:%=check-%)

check: $(TESTS)

check-%:
	./$*
