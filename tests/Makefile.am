VMOD_VTC = \
 test01.vtc\
 test03.vtc\
 time00.vtc

VMOD_VTI = \
 test00.vti\
 test02.vti

BUILT_TESTS = $(VMOD_VTI:.vti=.vtc)

VMOD_TESTS = \
 test00.vti\
 test01.vtc\
 test02.vti\
 test03.vtc\
 time00.vtc

.vti.vtc:
	sed 's/^#VARNISH$(VARNISHVERSION)#//' $< > $@

EXTRA_DIST=$(VMOD_VTC) $(VMOD_VTI)
CLEANFILES=$(BUILT_TESTS)

distclean-local:
	rm -fr tbf

check: $(BUILT_TESTS)
	for t in $(VMOD_TESTS); do \
	    n=$${t%%.vti}; \
	    if [ $$n != $$t ]; then \
		t=$(abs_builddir)/$${n}.vtc;\
	    else \
		t=$(abs_srcdir)/$$t;\
	    fi; \
	    $(VARNISHSRC)/bin/varnishtest/varnishtest \
                    -Dvarnishd=$(VARNISHSRC)/bin/varnishd/varnishd \
	            -Dvmod_topsrc=$(abs_top_srcdir) \
                    -Dvmod_topbuild=$(abs_top_builddir) $$t; \
        done
