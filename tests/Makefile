.PHONY: all

# we currently don't install the tests
# it could however be nice to have a "twopence-testsuite" package someday

all install: ;

tests:
	: >summary
	set -x; \
	for plugin in virtio ssh; do \
		for test in shell_test.sh python_test.py ruby_test.sh; do \
			api=$${test/_test*}; \
			./run-one $$plugin ./$$test | tee logfile; \
			set -- `sed '/^### SUMMARY \(.*\)/!d;s//\1/' logfile`; \
			printf "%-10s %-10s %9u %9u %9u %9u\n" $$plugin $$api $$* >>summary; \
			mv logfile logfile.$$plugin-$$api; \
		done; \
	done
	printf "%-10s %-10s %9s %9s %9s %9s\n" plugin api total skipped failed error
	cat summary

clean distclean:
	rm -f logfile logfile.* summary
