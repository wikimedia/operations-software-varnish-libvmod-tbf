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
#include <errno.h>
#include <time.h>

VCL_VOID
vmod_sleep(MOD_CTX ctx, VCL_REAL t)
{
	struct timespec ts, ret;

	ts.tv_sec = t;
	ts.tv_nsec = (t - ts.tv_sec) * 1e9;

	while (nanosleep(&ts, &ret) && errno == EINTR)
		ts = ret;
}
