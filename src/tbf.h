/* This file is part of vmod-tbf
   Copyright (C) 2013-2016 Sergey Poznyakoff
  
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
#include <stdbool.h>
#include <syslog.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/time.h>
#include "vrt.h"
#include "vcc_if.h"
#include "pthread.h"

#include "bin/varnishd/cache/cache.h"
#define MOD_CTX const struct vrt_ctx *
#define WSPTR(s) ((s)->ws)
