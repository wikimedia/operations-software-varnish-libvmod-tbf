# This file is part of vmod-tbf
# Copyright (C) 2013-2014 Sergey Poznyakoff
#
# Vmod-tbf is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# Vmod-tbf is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with vmod-tbf.  If not, see <http://www.gnu.org/licenses/>.

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
