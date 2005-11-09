/*
 *
 *   Copyright (C) International Business Machines  Corp., 2005
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 2.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */


#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

#include <openssl/evp.h>

#include <trousers/tss.h>
#include <trousers/trousers.h>

#define print_error(a,b) \
	fprintf(stderr, "%s:%d %s result: 0x%x (%s)\n", __FILE__, __LINE__, \
		a, b, Trspi_Error_String(b))

static struct option long_options[] = {
	{"enc-scheme", 1, 0, 'e'},
	{"sig-scheme", 1, 0, 'q'},
	{"key-size", 1, 0, 's'},
	{"auth", 0, 0, 'a'},
	{"popup", 0, 0, 'p'},
	{"help", 0, 0, 'h'},
	{0, 0, 0, 0}
};

void
usage(char *argv0)
{
	fprintf(stderr, "\t%s: create a TPM key and write it to disk\n"
		"\tusage: %s [options] <filename>\n\n"
		"\tOptions:\n"
		"\t\t-e|--enc-scheme\tencryption scheme to use [PKCSV15] or OAEP\n"
		"\t\t-q|--sig-scheme\tsignature scheme to use [DER] or SHA1\n"
		"\t\t-s|--key-size\tkey size in bits [2048]\n"
		"\t\t-a|--auth\trequire a password for the key [NO]\n"
		"\t\t-p|--popup\tuse TSS GUI popup dialogs to get the password "
		"for the\n\t\t\t\tkey [NO] (implies --auth)\n"
		"\t\t-h|--help\tprint this help message\n"
		"\nReport bugs to %s\n",
		argv0, argv0, PACKAGE_BUGREPORT);
	exit(-1);
}

TSS_UUID SRK_UUID = TSS_UUID_SRK;

int main(int argc, char **argv)
{
	TSS_HCONTEXT	hContext;
	TSS_FLAG	initFlags = TSS_KEY_TYPE_LEGACY | TSS_KEY_VOLATILE;
	TSS_HKEY	hKey;
	TSS_HKEY	hSRK;
	TSS_RESULT	result;
	TSS_HPOLICY	srkUsagePolicy, keyUsagePolicy;
	BYTE		*blob;
	UINT32		blob_size, srk_authusage;
	FILE		*out;
	char		*filename, c;
	int		option_index, auth = 0, popup = 0;
	UINT32		enc_scheme = TSS_ES_RSAESPKCSV15;
	UINT32		sig_scheme = TSS_SS_RSASSAPKCS1V15_DER;
	UINT32		key_size = 2048;

	while (1) {
		option_index = 0;
		c = getopt_long(argc, argv, "pe:q:s:ah",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 'a':
				initFlags |= TSS_KEY_AUTHORIZATION;
				auth = 1;
				break;
			case 'h':
				usage(argv[0]);
				break;
			case 's':
				key_size = atoi(optarg);
				break;
			case 'e':
				if (!strncasecmp("oaep", optarg, 4)) {
					enc_scheme = TSS_ES_RSAESOAEP_SHA1_MGF1;
				} else if (strncasecmp("pkcs", optarg, 4)) {
					usage(argv[0]);
				}
				break;
			case 'q':
				if (!strncasecmp("der", optarg, 3)) {
					sig_scheme = TSS_SS_RSASSAPKCS1V15_SHA1;
				} else if (strncasecmp("sha", optarg, 3)) {
					usage(argv[0]);
				}
				break;
			case 'p':
				initFlags |= TSS_KEY_AUTHORIZATION;
				auth = 1;
				popup = 1;
				break;
			default:
				usage(argv[0]);
				break;
		}
	}

	/* set up the key option flags */
	switch (key_size) {
		case 512:
			initFlags |= TSS_KEY_SIZE_512;
			break;
		case 1024:
			initFlags |= TSS_KEY_SIZE_1024;
			break;
		case 2048:
			initFlags |= TSS_KEY_SIZE_2048;
			break;
		case 4096:
			initFlags |= TSS_KEY_SIZE_4096;
			break;
		case 8192:
			initFlags |= TSS_KEY_SIZE_8192;
			break;
		case 16384:
			initFlags |= TSS_KEY_SIZE_16384;
			break;
		default:
			usage(argv[0]);
			break;
	}
#if 0
	while (argc--) {
		printf("argv[%d] = \"%s\"\n", argc, argv[argc]);
	}
	exit(1);
#endif
	filename = argv[argc - 1];
	if (argc < 2 || filename[0] == '-')
		usage(argv[0]);

		//Create Context
	if ((result = Tspi_Context_Create(&hContext))) {
		print_error("Tspi_Context_Create", result);
		exit(result);
	}
		//Connect Context
	if ((result = Tspi_Context_Connect(hContext, NULL))) {
		print_error("Tspi_Context_Connect", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Create Object
	if ((result = Tspi_Context_CreateObject(hContext,
						TSS_OBJECT_TYPE_RSAKEY,
						initFlags, &hKey))) {
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	if ((result = Tspi_SetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
					   TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
					   sig_scheme))) {
		print_error("Tspi_SetAttribUint32", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	if ((result = Tspi_SetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
					   TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
					   enc_scheme))) {
		print_error("Tspi_SetAttribUint32", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Load Key By UUID
	if ((result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM,
						 SRK_UUID, &hSRK))) {
		print_error("Tspi_Context_LoadKeyByUUID", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	if ((result = Tspi_GetAttribUint32(hSRK, TSS_TSPATTRIB_KEY_INFO,
					   TSS_TSPATTRIB_KEYINFO_AUTHUSAGE,
					   &srk_authusage))) {
		print_error("Tspi_GetAttribUint32", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	if (srk_authusage) {
		BYTE *authdata = calloc(1, 128);

		if (!authdata) {
			fprintf(stderr, "malloc failed.\n");
			Tspi_Context_Close(hContext);
			exit(result);
		}

		if ((result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE,
						   &srkUsagePolicy))) {
			print_error("Tspi_GetPolicyObject", result);
			Tspi_Context_CloseObject(hContext, hKey);
			Tspi_Context_Close(hContext);
			free(authdata);
			exit(result);
		}

		if (EVP_read_pw_string(authdata, 128, "SRK Password: ", 0)) {
			Tspi_Context_CloseObject(hContext, hKey);
			Tspi_Context_Close(hContext);
			free(authdata);
			exit(result);
		}

		//Set Secret
		if ((result = Tspi_Policy_SetSecret(srkUsagePolicy,
						    TSS_SECRET_MODE_PLAIN,
						    strlen(authdata),
						    authdata))) {
			print_error("Tspi_Policy_SetSecret", result);
			free(authdata);
			Tspi_Context_Close(hContext);
			exit(result);
		}

		free(authdata);
	}

	if (auth) {
		//Get Policy Object
		if ((result = Tspi_GetPolicyObject(hKey, TSS_POLICY_USAGE,
						   &keyUsagePolicy))) {
			print_error("Tspi_GetPolicyObject", result);
			Tspi_Context_CloseObject(hContext, hKey);
			Tspi_Context_Close(hContext);
			exit(result);
		}

		if (popup) {
			//Set Secret
			if ((result = Tspi_Policy_SetSecret(keyUsagePolicy,
							    TSS_SECRET_MODE_POPUP,
							    0, NULL))) {
				print_error("Tspi_Policy_SetSecret", result);
				Tspi_Context_Close(hContext);
				exit(result);
			}
		} else {
			BYTE *authdata = calloc(1, 128);

			if (!authdata) {
				fprintf(stderr, "malloc failed.\n");
				Tspi_Context_Close(hContext);
				exit(result);
			}

			if (EVP_read_pw_string(authdata, 128,
						"Enter Password: ", 1)) {
				printf("Passwords do not match.\n");
				free(authdata);
				Tspi_Context_Close(hContext);
				exit(result);
			}

			//Set Secret
			if ((result = Tspi_Policy_SetSecret(keyUsagePolicy,
							    TSS_SECRET_MODE_PLAIN,
							    strlen(authdata),
							    authdata))) {
				print_error("Tspi_Policy_SetSecret", result);
				free(authdata);
				Tspi_Context_Close(hContext);
				exit(result);
			}

			free(authdata);
		}
	}

		//Create Key
	if ((result = Tspi_Key_CreateKey(hKey, hSRK, 0))) {
		print_error("Tspi_Key_CreateKey", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(1);
	}

	if ((result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB,
					 TSS_TSPATTRIB_KEYBLOB_BLOB,
					 &blob_size, &blob))) {
		print_error("Tspi_GetAttribData", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(1);
	}

	if ((out = fopen(filename, "w")) == NULL) {
		print_error("fopen", errno);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(1);
	}

	if (fwrite(blob, blob_size, 1, out) != 1) {
		print_error("fwrite", errno);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		fclose(out);
		exit(1);
	}

	fclose(out);
	Tspi_Context_Close(hContext);

	printf("Success.\n");

	return 0;
}
