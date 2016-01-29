# This file is part of vmod-tbf
# Copyright (C) 2013-2016 Sergey Poznyakoff
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

VMOD_TESTS = \
 test00.vtc\
 test01.vtc\
 test02.vtc\
 test03.vtc\
 test05.vtc\
 time00.vtc

EXTRA_DIST=$(VMOD_TESTS)

distclean-local:
	$(AM_V_at)rm -fr tbf

check: $(BUILT_TESTS)
	$(AM_V_at)for t in $(VMOD_TESTS); do \
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
