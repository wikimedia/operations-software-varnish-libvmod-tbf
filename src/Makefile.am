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

AM_CPPFLAGS=\
 -I$(VARNISHSRC)/include\
 -I$(VARNISHSRC)/bin/varnishd\
 -I$(VARNISHSRC)\
 -DLOCALSTATEDIR=\"$(localstatedir)\"

dist_man_MANS=vmod-tbf.3 vmod_tbf.3

vmoddir = $(VMODDIR)
vmod_LTLIBRARIES = libvmod_tbf.la

libvmod_tbf_la_LDFLAGS=-module -export-dynamic -avoid-version
libvmod_tbf_la_LIBADD=

libvmod_tbf_la_SOURCES = \
	tbf.c\
        tbf.h\
        getla.c\
        sleep.c\
        time.c
nodist_libvmod_tbf_la_SOURCES = \
	vcc_if.c vcc_if.h

tbf.lo: vcc_if.h

CLEANFILES = vcc_if.c vcc_if.h *.rst

vmodtool = $(VARNISHSRC)/lib/libvcc/vmodtool.py
vmodtoolargs = --strict
vccfile = $(top_srcdir)/src/vmod_tbf.vcc

vcc_if.c vcc_if.h: $(vmodtool) $(vccfile)
	@PYTHON@ $(vmodtool) $(vmodtoolargs) $(vccfile)

EXTRA_DIST = \
	vmod_tbf.vcc


