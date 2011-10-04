/*!	\file setup.c
 *
 *	\brief Routines for the KP-ABE Setup.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include "celia.h"
#include "common.h"
#include "policy_lang.h"

char* usage =
"Usage: kpabe-setup [OPTION ...] ATTR [ATTR ...]\n"
"\n"
"Generate system parameters, a public key, and a master secret key\n"
"for use with kpabe-keygen, kpabe-enc, and kpabe-dec.\n"
"\n"
"Attributes come in two forms: non-numerical and numerical. Non-numerical\n"
"attributes are simply any string of letters, digits, and underscores\n"
"beginning with a letter.\n"
"\n"
"Numerical attributes are specified as `attr = N', where N is a non-negative\n"
"integer less than 2^64 and `attr' is another string. The whitespace around\n"
"the `=' is optional. One may specify an explicit length of k bits for the\n"
"integer by giving `attr = N#k'. Note that any comparisons in a policy given\n"
"to kpabe-keygen (1) must then specify the same number of bits, e.g.,\n"
"`attr > 5#12'.\n"
"\n"
"The keywords `and', `or', and `of', are reserved for the policy language\n"
"of kpabe-keygen (1) and may not be used for either type of attribute.\n"
"\n"
"Output will be written to the files \"pub_key\" and \"master_key\"\n"
"unless the --output-public-key or --output-master-key options are\n"
"used.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help                    print this message\n\n"
" -v, --version                 print version information\n\n"
" -p, --output-public-key FILE  write public key to FILE\n\n"
" -m, --output-master-key FILE  write master secret key to FILE\n\n"
" -d, --deterministic           use deterministic \"random\" numbers\n"
"                               (only for debugging)\n\n"
"";

char* pub_file = "pub_key";
char* msk_file = "master_key";
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
			printf(KPABE_VERSION, "-setup");
			exit(0);
		}
		else if( !strcmp(argv[i], "-p") || !strcmp(argv[i], "--output-public-key") )
		{
			if( ++i >= argc )
				die(usage);
			else
				pub_file = argv[i];
		}
		else if( !strcmp(argv[i], "-m") || !strcmp(argv[i], "--output-master-key") )
		{
			if( ++i >= argc )
				die(usage);
			else
				msk_file = argv[i];
		}
		else if( !strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic") )
		{
			pbc_random_set_deterministic(0);
		}
		else
		{
			parse_attribute_universe(&alist, argv[i]);
		}

		if( !pub_file || !msk_file || !alist )
			die(usage);

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
	kpabe_msk_t* msk;

	parse_args(argc, argv);

	kpabe_setup(&pub, &msk, attrs);
	spit_file(pub_file, kpabe_pub_serialize(pub), 1);
	spit_file(msk_file, kpabe_msk_serialize(msk), 1);

	return 0;
}
