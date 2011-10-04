/*!	\file dec.c
 *
 *	\brief Routines for the KP-ABE Decryption.
 *
 *	Copyright 2011 Yao Zheng.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.

 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <assert.h>
#include <pbc.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc_random.h>

#include "celia.h"
#include "common.h"

char* usage =
"Usage: kpabe-dec [OPTION ...] PUB_KEY PRIV_KEY FILE\n"
"\n"
"Decrypt FILE using private key PRIV_KEY and assuming public key\n"
"PUB_KEY. If the name of FILE is X.kpabe, the decrypted file will\n"
"be written as X and FILE will be removed. Otherwise the file will be\n"
"decrypted in place. Use of the -o option overrides this\n"
"behavior.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -k, --keep-input-file    don't delete original file\n\n"
" -o, --output FILE        write output to FILE\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";

char* pub_file   = 0;
char* prv_file   = 0;
char* in_file    = 0;
char* out_file   = 0;
int   keep       = 0;

void
parse_args( int argc, char** argv )
{
	int i;

	for( i = 1; i < argc; i++ )
		if(      !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
		{
			printf("%s", usage);
			exit(0);
		}
		else if( !strcmp(argv[i], "-v") || !strcmp(argv[i], "--version") )
		{
			printf(KPABE_VERSION, "-dec");
			exit(0);
		}
		else if( !strcmp(argv[i], "-k") || !strcmp(argv[i], "--keep-input-file") )
		{
			keep = 1;
		}
		else if( !strcmp(argv[i], "-o") || !strcmp(argv[i], "--output") )
		{
			if( ++i >= argc )
				die(usage);
			else
				out_file = argv[i];
		}
		else if( !strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic") )
		{
			pbc_random_set_deterministic(0);
		}
		else if( !pub_file )
		{
			pub_file = argv[i];
		}
		else if( !prv_file )
		{
			prv_file = argv[i];
		}
		else if( !in_file )
		{
			in_file = argv[i];
		}
		else
			die(usage);

	if( !pub_file || !prv_file || !in_file )
		die(usage);

	if( !out_file )
	{
		if(  strlen(in_file) > 6 &&
				!strcmp(in_file + strlen(in_file) - 6, ".kpabe") )
			out_file = g_strndup(in_file, strlen(in_file) - 6);
		else
			out_file = strdup(in_file);
	}

	if( keep && !strcmp(in_file, out_file) )
		die("cannot keep input file when decrypting file in place (try -o)\n");
}

int
main( int argc, char** argv )
{
	kpabe_pub_t* pub;
	kpabe_prv_t* prv;
	int file_len;
	GByteArray* aes_buf;
	GByteArray* plt;
	GByteArray* cph_buf;
	kpabe_cph_t* cph;
	element_t m;

	parse_args(argc, argv);

	pub = kpabe_pub_unserialize(suck_file(pub_file), 1);
	prv = kpabe_prv_unserialize(pub, suck_file(prv_file), 1);

	read_kpabe_file(in_file, &cph_buf, &file_len, &aes_buf);

	cph = kpabe_cph_unserialize(pub, cph_buf, 1);
	if( !kpabe_dec(pub, prv, cph, m) )
		die("%s", kpabe_error());
	kpabe_cph_free(cph);

	plt = aes_128_cbc_decrypt(aes_buf, m);
	g_byte_array_set_size(plt, file_len);
	g_byte_array_free(aes_buf, 1);

	spit_file(out_file, plt, 1);

	if( !keep )
		unlink(in_file);

	return 0;
}
