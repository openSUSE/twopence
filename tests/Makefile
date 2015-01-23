.PHONY: all

# we currently don't install the tests
# it could however be nice to have a "twopence-testsuite" package someday

all:
	set -e; for access_method in virtio; do \
		for test in test.sh test.py test.rb; do \
			./run-$$access_method ./$$test; \
		done; \
	done
