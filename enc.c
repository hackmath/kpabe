/*!	\file enc.c
 *
 *	\brief Routines for the KP-ABE Encryption.
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

#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include "celia.h"
#include "common.h"
#include "policy_lang.h"

char* usage =
"Usage: kpabe-enc [OPTION ...] PUB_KEY FILE ATTR [ATTR ...]\n"
"\n"
"Encrypt FILE under a set of attributes(ATTR) using public key\n"
"PUB_KEY. The encrypted file will be written to FILE.kpabe unless\n"
"the -o option is used. The original file will be removed."
"\n"
"Attributes come in two forms: non-numerical and numerical. Non-numerical\n"
"attributes are simply any string of letters, digits, and underscores\n"
"beginning with a letter.\n"
"\n"
"Numerical attributes are specified as `attr = N', where N is a non-negative\n"
"integer less than 2^64 and `attr' is another string. The whitespace around\n"
"the `=' is optional. One may specify an explicit length of k bits for the\n"
"integer by giving `attr = N#k'. Note that any comparisons in a policy given\n"
"to kpabe-enc(1) must then specify the same number of bits, e.g.,\n"
"`attr > 5#12'.\n"
"\n"
"The keywords `and', `or', and `of', are reserved for the policy language\n"
"of kpabe-enc (1) and may not be used for either type of attribute.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -k, --keep-input-file    don't delete original file\n\n"
" -o, --output FILE        write resulting ciphertext to FILE\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";

/*
	TODO ensure we don't give out the same attribute more than once (esp
	as different numerical values),or give out attribute that not include
	in the attribute universe
*/

char* pub_file = 0;
char* in_file  = 0;
char* out_file = 0;
int   keep     = 0;

char** attrs    = 0;

gint
comp_string( gconstpointer a, gconstpointer b)
{
	return strcmp(a, b);
}

void
parse_args( int argc, char** argv )
{
	int i;
	GSList* alist;
	GSList* ap;
	int n;

	alist = 0;
	for( i = 1; i < argc; i++ )
		if(      !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
		{
			printf("%s", usage);
			exit(0);
		}
		else if( !strcmp(argv[i], "-v") || !strcmp(argv[i], "--version") )
		{
			printf(KPABE_VERSION, "-enc");
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
		else if( !in_file )
		{
			in_file = argv[i];
		}
		else
		{
			parse_attribute(&alist, argv[i]);
		}

	if( !pub_file || !in_file || !alist )
		die(usage);

	if( !out_file )
		out_file = g_strdup_printf("%s.kpabe", in_file);

	alist = g_slist_sort(alist, comp_string);
	n = g_slist_length(alist);

	attrs = malloc((n + 1) * sizeof(char*));

	i = 0;
	for( ap = alist; ap; ap = ap->next )
		attrs[i++] = ap->data;
	attrs[i] = 0;
}

int
main( int argc, char** argv )
{
	kpabe_pub_t* pub;
	kpabe_cph_t* cph;
	int file_len;
	GByteArray* plt;
	GByteArray* cph_buf;
	GByteArray* aes_buf;
	element_t m;

	parse_args(argc, argv);

	pub = kpabe_pub_unserialize(suck_file(pub_file), 1);

  if( !(cph = kpabe_enc(pub, m, attrs)) )
		die("%s", kpabe_error());
	free(attrs);

	cph_buf = kpabe_cph_serialize(cph);
	kpabe_cph_free(cph);

	plt = suck_file(in_file);
	file_len = plt->len;
	aes_buf = aes_128_cbc_encrypt(plt, m);
	g_byte_array_free(plt, 1);
	element_clear(m);

	write_kpabe_file(out_file, cph_buf, file_len, aes_buf);

	g_byte_array_free(cph_buf, 1);
	g_byte_array_free(aes_buf, 1);

	if( !keep )
		unlink(in_file);

	return 0;
}
