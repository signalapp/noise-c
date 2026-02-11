
SUBDIRS = include src tools tests doc

if ENABLE_EXAMPLES
SUBDIRS += examples
endif

EXTRA_DIST = README.md

docs:
	(cd $(srcdir)/doc; $(DOXYGEN))
