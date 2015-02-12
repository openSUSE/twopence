.PHONY: all

# we currently don't install the tests
# it could however be nice to have a "twopence-testsuite" package someday

all:
	set -e; for access_method in virtio ssh; do \
		for test in shell_test.sh python_test.py ruby_test.sh; do \
			./run-one $$access_method ./$$test; \
		done; \
	done
