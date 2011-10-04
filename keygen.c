/*!	\file keygen.c
 *
 *	\brief Routines for the KP-ABE Key Generation.
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
#include <strings.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include "celia.h"
#include "common.h"
#include "policy_lang.h"

char* usage =
"Usage: kpabe-keygen [OPTION ...] PUB_KEY MASTER_KEY [POLICY]\n"
"\n"
"Generate a key under the decryption policy POLICY using public key\n"
"PUB_KEY and master secret key MASTER_KEY. Output will be written to the file\n"
"\"priv_key\" unless the -o option is specified.\n"
"\n"
"If POLICY is not specified, the policy will be read from stdin.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -o, --output FILE        write resulting key to FILE\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";

/*
	TODO ensure we don't give out the same attribute more than once (esp
	as different numerical values)
*/

char*  pub_file = 0;
char*  msk_file = 0;
char*  policy = 0;

char*  out_file = "priv_key";

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
			printf(KPABE_VERSION, "-keygen");
			exit(0);
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
		else if( !msk_file )
		{
			msk_file = argv[i];
		}
		else if( !policy )
		{
			policy = parse_policy_lang(argv[i]);
		}
		else
			die(usage);

	if( !pub_file || !msk_file )
		die(usage);

	if( !policy )
		policy = parse_policy_lang(suck_stdin());
}

int
main( int argc, char** argv )
{
	kpabe_pub_t* pub;
	kpabe_msk_t* msk;
	kpabe_prv_t* prv;

	parse_args(argc, argv);

	pub = kpabe_pub_unserialize(suck_file(pub_file), 1);
	msk = kpabe_msk_unserialize(pub, suck_file(msk_file), 1);

  if( !(prv = kpabe_keygen(pub, msk, policy)) )
		die("%s", kpabe_error());
	free(policy);
	spit_file(out_file, kpabe_prv_serialize(prv), 1);

	return 0;
}

