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
#define _BSD_SOURCE
#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#if defined(HAVE_SYSINFO) && defined(HAVE_SYS_SYSINFO_H)
# include <sys/sysinfo.h>
#endif
#include "vrt.h"
#include "vcc_if.h"

double
vmod_getla(struct sess *sp, int what)
{
	switch (what) {
	case 1:
		what = 0;
		break;
	case 5:
		what = 1;
		break;
	case 15:
		what = 2;
		break;
	default:
		what = 0;
	}
	
#if defined(HAVE_GETLOADAVG)
	double loadavg[3];
	
	if (getloadavg(loadavg, 3) != 3) {
		syslog(LOG_DAEMON|LOG_CRIT, "tbf.getla cannot get values");
		return 0.0;
	}
	return loadavg[what];
#elif defined(HAVE_SYSINFO) && defined(HAVE_SYS_SYSINFO_H)
	struct sysinfo info;

	if (sysinfo(&info)) {
		syslog(LOG_DAEMON|LOG_CRIT, "tbf.getla cannot get values");
		return 0.0;
	}
	return info.loads[what] / 65536.0; 
#else
	syslog(LOG_DAEMON|LOG_CRIT, "tbf.getla is not implemented");
	return 0.0;
#endif	
}
