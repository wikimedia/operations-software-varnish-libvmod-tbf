/* This file is part of vmod-tbf
   Copyright (C) 2013 Sergey Poznyakoff
  
   Vmod-tbf is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.
  
   Vmod-tbf is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with vmod-tbf.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "vrt.h"
#include "vcc_if.h"
#include "bin/varnishd/cache.h"

int
vmod_systime(struct sess *sp)
{
	return time(NULL);
}

const char *
vmod_strftime(struct sess *sp, const char *format, int timestamp)
{
	time_t ts = (time_t) timestamp;
	size_t u, n;
	char *p;
	
	u = WS_Reserve(sp->wrk->ws, 0);
        p = sp->wrk->ws->f;
        n = strftime(p, u, format, gmtime(&ts));
	if (n == 0) {
		WS_Release(sp->wrk->ws, 0);
		return NULL;
	}

	WS_Release(sp->wrk->ws, n + 1);

	return p;
}
