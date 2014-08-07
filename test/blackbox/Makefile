BLACKBOX_ALL:=$(wildcard test/blackbox/test-*.sh)
BLACKBOX_TESTS:=$(BLACKBOX_ALL:%=check-%)

check: blackbox-check

blackbox-check: $(BLACKBOX_TESTS)

$(BLACKBOX_ALL): $(BINS)

$(BLACKBOX_TESTS): check-test/blackbox/%: test/blackbox/%
	@$(RM) -r $<-dir && mkdir $<-dir
	@ulimit -c unlimited; if SCRATCHDIR="$<-dir" RUNPREFIX="./" $< > $<-dir/output 2>&1; then printf "[BLACKBOX] %-44s OK\n" $*; exit 0; else printf "[BLACKBOX] %-44s FAIL\n" $*; cat $<-dir/output; exit 1; fi

test-clean: test-blackbox-clean
test-distclean: test-blackbox-distclean

test-blackbox-clean:
	$(RM) -r $(BLACKBOX_TESTS:%=%-dir)

test-blackbox-distclean:

