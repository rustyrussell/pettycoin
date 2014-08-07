ALL:=$(wildcard test-*.sh)
TESTS:=$(ALL:%=check-%)

check: $(TESTS)

check-%:
	$(RM) -r $*-dir
	ulimit -c unlimited && mkdir $*-dir && ./$* $*-dir
