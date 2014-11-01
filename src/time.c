/* This file is part of vmod-tbf
   Copyright (C) 2013-2014 Sergey Poznyakoff
  
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
#include "tbf.h"
#include <time.h>

VCL_INT
vmod_systime(MOD_CTX ctx)
{
	return time(NULL);
}

VCL_STRING
vmod_strftime(MOD_CTX ctx, VCL_STRING format, VCL_INT timestamp)
{
	time_t ts = (time_t) timestamp;
	size_t u, n;
	char *p;
	
	u = WS_Reserve(WSPTR(ctx), 0);
        p = WSPTR(ctx)->f;
        n = strftime(p, u, format, gmtime(&ts));
	if (n == 0) {
		WS_Release(WSPTR(ctx), 0);
		return NULL;
	}

	WS_Release(WSPTR(ctx), n + 1);

	return p;
}
