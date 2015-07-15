/*

  This file is provided under a dual BSD/GPLv2 license.  When using or
  redistributing this file, you may do so under either license.

  GPL LICENSE SUMMARY

  Copyright(c) 2015 Intel Corporation.

  This program is free software; you can redistribute it and/or modify
  it under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  Contact Information:
  Intel Corporation, www.intel.com

  BSD LICENSE

  Copyright(c) 2015 Intel Corporation.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

/* Copyright (c) 2003-2014 Intel Corporation. All rights reserved. */

/* This file contains a simple sysfs interface used by the low level
   hfi protocol code.  It also implements the interface to hfifs. */

#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "opa_service.h"

static char *sysfs_path;
static size_t sysfs_path_len;
static char *hfifs_path;
static long sysfs_page_size;

static void __attribute__ ((constructor)) sysfs_init(void)
{
	struct stat s;
	if (sysfs_path == NULL)
		sysfs_path = getenv("HFI_SYSFS_PATH");
	if (sysfs_path == NULL) {
		static char syspath[64];
		snprintf(syspath, sizeof(syspath), "%s_%d", HFI_CLASS_PATH, 0);
		sysfs_path = syspath;
	}
	if (stat(sysfs_path, &s) || !S_ISDIR(s.st_mode))
		_HFI_DBG("Did not find sysfs directory %s, using anyway\n",
			 sysfs_path);
	sysfs_path_len = strlen(sysfs_path);

	if (hfifs_path == NULL)
		hfifs_path = getenv("HFI_HFIFS_PATH");
	if (hfifs_path == NULL)
		hfifs_path = "/hfifs";

	if (!sysfs_page_size)
		sysfs_page_size = sysconf(_SC_PAGESIZE);
}

const char *hfi_sysfs_path(void)
{
	return sysfs_path;
}

size_t hfi_sysfs_path_len(void)
{
	return sysfs_path_len;
}

const char *hfi_hfifs_path(void)
{
	return hfifs_path;
}

int hfi_sysfs_open(const char *attr, int flags)
{
	char buf[1024];
	int saved_errno;
	int fd;

	snprintf(buf, sizeof(buf), "%s/%s", hfi_sysfs_path(), attr);
	fd = open(buf, flags);
	saved_errno = errno;

	if (fd == -1) {
		_HFI_DBG("Failed to open driver attribute '%s': %s\n", attr,
			 strerror(errno));
		_HFI_DBG("Offending file name: %s\n", buf);
	}

	errno = saved_errno;
	return fd;
}

int hfi_hfifs_open(const char *attr, int flags)
{
	char buf[1024];
	int saved_errno;
	int fd;

	snprintf(buf, sizeof(buf), "%s/%s", hfi_hfifs_path(), attr);
	fd = open(buf, flags);
	saved_errno = errno;

	if (fd == -1) {
		_HFI_DBG("Failed to open driver attribute '%s': %s\n", attr,
			 strerror(errno));
		_HFI_DBG("Offending file name: %s\n", buf);
	}

	errno = saved_errno;
	return fd;
}

static int sysfs_vprintf(int fd, const char *fmt, va_list ap)
{
	char *buf;
	int len, ret;
	int saved_errno;

	buf = alloca(sysfs_page_size);
	len = vsnprintf(buf, sysfs_page_size, fmt, ap);

	if (len > sysfs_page_size) {
		_HFI_DBG("Attempt to write more (%d) than %ld bytes\n", len,
			 sysfs_page_size);
		saved_errno = EINVAL;
		ret = -1;
		goto bail;
	}

	ret = write(fd, buf, len);
	saved_errno = errno;

	if (ret != -1 && ret < len) {
		_HFI_DBG("Write ran short (%d < %d)\n", ret, len);
		saved_errno = EAGAIN;
		ret = -1;
	}

bail:
	errno = saved_errno;
	return ret;
}

int hfi_sysfs_printf(const char *attr, const char *fmt, ...)
{
	int fd = -1;
	va_list ap;
	int ret = -1;
	int saved_errno;

	fd = hfi_sysfs_open(attr, O_WRONLY);
	saved_errno = errno;

	if (fd == -1) {
		goto bail;
	}

	va_start(ap, fmt);
	ret = sysfs_vprintf(fd, fmt, ap);
	saved_errno = errno;
	va_end(ap);

	if (ret == -1) {
		_HFI_DBG("Failed to write to driver attribute '%s': %s\n", attr,
			 strerror(errno));
	}

bail:
	if (fd != -1)
		close(fd);

	errno = saved_errno;
	return ret;
}

int hfi_sysfs_unit_open(uint32_t unit, const char *attr, int flags)
{
	int saved_errno;
	char buf[1024];
	int fd;
	int len, l;

	snprintf(buf, sizeof(buf), "%s", hfi_sysfs_path());
	len = l = strlen(buf) - 1;
	while (l > 0 && isdigit(buf[l]))
		l--;
	if (l)
		buf[++l] = 0;
	else
		l = len;	/* assume they know what they are doing */
	snprintf(buf + l, sizeof(buf) - l, "%u/%s", unit, attr);
	fd = open(buf, flags);
	saved_errno = errno;

	if (fd == -1) {
		_HFI_DBG("Failed to open attribute '%s' of unit %d: %s\n", attr,
			 unit, strerror(errno));
		_HFI_DBG("Offending file name: %s\n", buf);
	}

	errno = saved_errno;
	return fd;
}

int hfi_sysfs_port_open(uint32_t unit, uint32_t port, const char *attr,
			int flags)
{
	int saved_errno;
	char buf[1024];
	int fd;
	int len, l;

	snprintf(buf, sizeof(buf), "%s", hfi_sysfs_path());
	len = l = strlen(buf) - 1;
	while (l > 0 && isdigit(buf[l]))
		l--;
	if (l)
		buf[++l] = 0;
	else
		l = len;	/* assume they know what they are doing */
	snprintf(buf + l, sizeof(buf) - l, "%u/ports/%u/%s", unit, port, attr);
	fd = open(buf, flags);
	saved_errno = errno;

	if (fd == -1) {
		_HFI_DBG("Failed to open attribute '%s' of unit %d:%d: %s\n",
			 attr, unit, port, strerror(errno));
		_HFI_DBG("Offending file name: %s\n", buf);
	}

	errno = saved_errno;
	return fd;
}

int hfi_hfifs_unit_open(uint32_t unit, const char *attr, int flags)
{
	int saved_errno;
	char buf[1024];
	int fd;

	snprintf(buf, sizeof(buf), "%s/%u/%s", hfi_hfifs_path(), unit, attr);
	fd = open(buf, flags);
	saved_errno = errno;

	if (fd == -1) {
		_HFI_DBG("Failed to open attribute '%s' of unit %d: %s\n", attr,
			 unit, strerror(errno));
		_HFI_DBG("Offending file name: %s\n", buf);
	}

	errno = saved_errno;
	return fd;
}

int hfi_sysfs_port_printf(uint32_t unit, uint32_t port, const char *attr,
			  const char *fmt, ...)
{
	va_list ap;
	int ret = -1;
	int saved_errno;
	int fd;

	fd = hfi_sysfs_port_open(unit, port, attr, O_WRONLY);
	saved_errno = errno;

	if (fd == -1) {
		goto bail;
	}

	va_start(ap, fmt);
	ret = sysfs_vprintf(fd, fmt, ap);
	saved_errno = errno;
	va_end(ap);

	if (ret == -1) {
		_HFI_DBG("Failed to write to attribute '%s' of unit %d: %s\n",
			 attr, unit, strerror(errno));
	}

bail:
	if (fd != -1)
		close(fd);

	errno = saved_errno;
	return ret;
}

int hfi_sysfs_unit_printf(uint32_t unit, const char *attr, const char *fmt, ...)
{
	va_list ap;
	int ret = -1;
	int saved_errno;
	int fd;

	fd = hfi_sysfs_unit_open(unit, attr, O_WRONLY);
	saved_errno = errno;

	if (fd == -1) {
		goto bail;
	}

	va_start(ap, fmt);
	ret = sysfs_vprintf(fd, fmt, ap);
	saved_errno = errno;
	va_end(ap);

	if (ret == -1) {
		_HFI_DBG("Failed to write to attribute '%s' of unit %d: %s\n",
			 attr, unit, strerror(errno));
	}

bail:
	if (fd != -1)
		close(fd);

	errno = saved_errno;
	return ret;
}

static int read_page(int fd, char **datap)
{
	char *data = NULL;
	int saved_errno;
	int ret = -1;

	data = malloc(sysfs_page_size);
	saved_errno = errno;

	if (!data) {
		_HFI_DBG("Could not allocate memory: %s\n", strerror(errno));
		goto bail;
	}

	ret = read(fd, data, sysfs_page_size);
	saved_errno = errno;

	if (ret == -1) {
		_HFI_DBG("Read of attribute failed: %s\n", strerror(errno));
		goto bail;
	}

bail:
	if (ret == -1) {
		free(data);
	} else {
		*datap = data;
	}

	errno = saved_errno;
	return ret;
}

/*
 * On return, caller must free *datap.
 */
int hfi_sysfs_read(const char *attr, char **datap)
{
	int fd = -1, ret = -1;
	int saved_errno;

	fd = hfi_sysfs_open(attr, O_RDONLY);
	saved_errno = errno;

	if (fd == -1)
		goto bail;

	ret = read_page(fd, datap);
	saved_errno = errno;

bail:
	if (ret == -1)
		*datap = NULL;

	if (fd != -1) {
		close(fd);
	}

	errno = saved_errno;
	return ret;
}

/*
 * On return, caller must free *datap.
 */
int hfi_sysfs_unit_read(uint32_t unit, const char *attr, char **datap)
{
	int fd = -1, ret = -1;
	int saved_errno;

	fd = hfi_sysfs_unit_open(unit, attr, O_RDONLY);
	saved_errno = errno;

	if (fd == -1)
		goto bail;

	ret = read_page(fd, datap);
	saved_errno = errno;

bail:
	if (ret == -1)
		*datap = NULL;

	if (fd != -1) {
		close(fd);
	}

	errno = saved_errno;
	return ret;
}

/*
 * On return, caller must free *datap.
 */
int hfi_sysfs_port_read(uint32_t unit, uint32_t port, const char *attr,
			char **datap)
{
	int fd = -1, ret = -1;
	int saved_errno;

	fd = hfi_sysfs_port_open(unit, port, attr, O_RDONLY);
	saved_errno = errno;

	if (fd == -1)
		goto bail;

	ret = read_page(fd, datap);
	saved_errno = errno;

bail:
	if (ret == -1)
		*datap = NULL;

	if (fd != -1) {
		close(fd);
	}

	errno = saved_errno;
	return ret;
}

int hfi_sysfs_unit_write(uint32_t unit, const char *attr, const void *data,
			 size_t len)
{
	int fd = -1, ret = -1;
	int saved_errno;

	if (len > sysfs_page_size) {
		_HFI_DBG("Attempt to write more (%ld) than %ld bytes\n",
			 (long)len, sysfs_page_size);
		saved_errno = EINVAL;
		goto bail;
	}

	fd = hfi_sysfs_unit_open(unit, attr, O_WRONLY);
	saved_errno = errno;

	if (fd == -1)
		goto bail;

	ret = write(fd, data, len);
	saved_errno = errno;

	if (ret == -1) {
		_HFI_DBG("Attempt to write %ld bytes failed: %s\n",
			 (long)len, strerror(errno));
		goto bail;
	}

	if (ret < len) {
		/* sysfs routines can routine count including null byte
		   so don't return an error if it's > len */
		_HFI_DBG
		    ("Attempt to write %ld bytes came up short (%ld bytes)\n",
		     (long)len, (long)ret);
		saved_errno = EAGAIN;
		ret = -1;
	}

bail:
	if (fd != -1) {
		close(fd);
	}

	errno = saved_errno;
	return ret;
}

/*
 * On return, caller must free *datap.
 */
int hfi_hfifs_read(const char *attr, char **datap)
{
	int fd = -1, ret = -1;
	int saved_errno;

	fd = hfi_hfifs_open(attr, O_RDONLY);
	saved_errno = errno;

	if (fd == -1)
		goto bail;

	ret = read_page(fd, datap);
	saved_errno = errno;

bail:
	if (ret == -1)
		*datap = NULL;

	if (fd != -1) {
		close(fd);
	}

	errno = saved_errno;
	return ret;
}

/*
 * On return, caller must free *datap.
 */
int hfi_hfifs_unit_read(uint32_t unit, const char *attr, char **datap)
{
	int fd = -1, ret = -1;
	int saved_errno;

	fd = hfi_hfifs_unit_open(unit, attr, O_RDONLY);
	saved_errno = errno;

	if (fd == -1)
		goto bail;

	ret = read_page(fd, datap);
	saved_errno = errno;

bail:
	if (ret == -1)
		*datap = NULL;

	if (fd != -1) {
		close(fd);
	}

	errno = saved_errno;
	return ret;
}

/*
 * The _rd routines jread directly into a supplied buffer,
 * unlike  the _read routines.
 */
int hfi_hfifs_rd(const char *attr, void *buf, int n)
{
	int fd = -1, ret = -1;
	int saved_errno;

	fd = hfi_hfifs_open(attr, O_RDONLY);
	saved_errno = errno;

	if (fd == -1)
		goto bail;

	ret = read(fd, buf, n);
	saved_errno = errno;

bail:
	if (fd != -1) {
		close(fd);
	}

	errno = saved_errno;
	return ret;
}

int hfi_hfifs_unit_rd(uint32_t unit, const char *attr, void *buf, int n)
{
	int fd = -1, ret = -1;
	int saved_errno;

	fd = hfi_hfifs_unit_open(unit, attr, O_RDONLY);
	saved_errno = errno;

	if (fd == -1)
		goto bail;

	ret = read(fd, buf, n);
	saved_errno = errno;

bail:
	if (fd != -1) {
		close(fd);
	}

	errno = saved_errno;
	return ret;
}

int hfi_hfifs_unit_write(uint32_t unit, const char *attr, const void *data,
			 size_t len)
{
	int fd = -1, ret = -1;
	int saved_errno;

	fd = hfi_hfifs_unit_open(unit, attr, O_WRONLY);
	saved_errno = errno;

	if (fd == -1)
		goto bail;

	ret = write(fd, data, len);
	saved_errno = errno;

	if (ret == -1) {
		_HFI_DBG("Attempt to write %ld bytes failed: %s\n",
			 (long)len, strerror(errno));
		goto bail;
	}

	if (ret != len) {
		_HFI_DBG
		    ("Attempt to write %ld bytes came up short (%ld bytes)\n",
		     (long)len, (long)ret);
		saved_errno = EAGAIN;
		ret = -1;
	}

bail:
	if (fd != -1) {
		close(fd);
	}

	errno = saved_errno;
	return ret;
}

int hfi_sysfs_read_s64(const char *attr, int64_t *valp, int base)
{
	char *data, *end;
	int ret;
	int saved_errno;
	long long val;

	ret = hfi_sysfs_read(attr, &data);
	saved_errno = errno;

	if (ret == -1) {
		goto bail;
	}

	val = strtoll(data, &end, base);
	saved_errno = errno;

	if (!*data || !(*end == '\0' || isspace(*end))) {
		ret = -1;
		goto bail;
	}

	*valp = val;
	ret = 0;

bail:
	free(data);
	errno = saved_errno;
	return ret;
}

int hfi_sysfs_unit_read_s64(uint32_t unit, const char *attr,
			    int64_t *valp, int base)
{
	char *data, *end;
	int saved_errno;
	long long val;
	int ret;

	ret = hfi_sysfs_unit_read(unit, attr, &data);
	saved_errno = errno;

	if (ret == -1) {
		goto bail;
	}

	val = strtoll(data, &end, base);
	saved_errno = errno;

	if (!*data || !(*end == '\0' || isspace(*end))) {
		ret = -1;
		goto bail;
	}

	*valp = val;
	ret = 0;

bail:
	free(data);
	errno = saved_errno;
	return ret;
}

int hfi_sysfs_port_read_s64(uint32_t unit, uint32_t port, const char *attr,
			    int64_t *valp, int base)
{
	char *data, *end;
	int saved_errno;
	long long val;
	int ret;

	ret = hfi_sysfs_port_read(unit, port, attr, &data);
	saved_errno = errno;

	if (ret == -1) {
		goto bail;
	}

	val = strtoll(data, &end, base);
	saved_errno = errno;

	if (!*data || !(*end == '\0' || isspace(*end))) {
		ret = -1;
		goto bail;
	}

	*valp = val;
	ret = 0;

bail:
	free(data);
	errno = saved_errno;
	return ret;
}
