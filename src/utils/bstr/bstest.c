/*
 * This source file is part of the bstring string library.  This code was
 * written by Paul Hsieh in 2002-2015, and is covered by the BSD open source
 * license. Refer to the accompanying documentation for details on usage and
 * license.
 */

/*
 * bstest.c
 *
 * This file is the C unit test for Bstrlib.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>
#include <ctype.h>
#include "bstrlib.h"
#include "bstraux.h"

static bstring dumpOut[16];
static int rot = 0;

static int incorrectBstring (const struct tagbstring * b) {
	if (NULL == b) return 1;
	if (NULL == b->data) return 1;
	if (b->slen < 0) return 1;
	if (b->mlen > 0 && b->slen > b->mlen) return 1;
	if (b->data[b->slen] != '\0') return 1;
	return 0;
}

static char * dumpBstring (const struct tagbstring * b) {
	rot = (rot + 1) % (unsigned)16;
	if (dumpOut[rot] == NULL) {
		dumpOut[rot] = bfromcstr ("");
		if (dumpOut[rot] == NULL) return "FATAL INTERNAL ERROR";
	}
	dumpOut[rot]->slen = 0;
	if (b == NULL) {
		bcatcstr (dumpOut[rot], "NULL");
	} else {
		static char msg[256];
		sprintf (msg, "%p", (void *)b);
		bcatcstr (dumpOut[rot], msg);

		if (b->slen < 0) {
			sprintf (msg, ":[err:slen=%d<0]", b->slen);
			bcatcstr (dumpOut[rot], msg);
		} else {
			if (b->mlen > 0 && b->mlen < b->slen) {
				sprintf (msg, ":[err:mlen=%d<slen=%d]", b->mlen, b->slen);
				bcatcstr (dumpOut[rot], msg);
			} else {
				if (b->mlen == -1) {
					bcatcstr (dumpOut[rot], "[p]");
				} else if (b->mlen < 0) {
					bcatcstr (dumpOut[rot], "[c]");
				}
				bcatcstr (dumpOut[rot], ":");
				if (b->data == NULL) {
					bcatcstr (dumpOut[rot], "[err:data=NULL]");
				} else {
					bcatcstr (dumpOut[rot], "\"");
					bcatcstr (dumpOut[rot], (const char *) b->data);
					bcatcstr (dumpOut[rot], "\"");
				}
			}
		}
	}
	return (char *) dumpOut[rot]->data;
}

static char* dumpCstring (const char* s) {
	rot = (rot + 1) % (unsigned)16;
	if (dumpOut[rot] == NULL) {
		dumpOut[rot] = bfromcstr ("");
		if (dumpOut[rot] == NULL) return "FATAL INTERNAL ERROR";
	}
	dumpOut[rot]->slen = 0;
	if (s == NULL) {
		bcatcstr (dumpOut[rot], "NULL");
	} else {
		static char msg[64];
		int i;

		sprintf (msg, "cstr[%p] -> ", (void *)s);
		bcatcstr (dumpOut[rot], msg);

		bcatStatic (dumpOut[rot], "\"");
		for (i = 0; s[i]; i++) {
			if (i > 1024) {
				bcatStatic (dumpOut[rot], " ...");
				break;
			}
			bconchar (dumpOut[rot], s[i]);
		}
		bcatStatic (dumpOut[rot], "\"");
	}

	return (char *) dumpOut[rot]->data;
}
