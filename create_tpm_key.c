/*
 *
 *   Copyright (C) International Business Machines  Corp., 2004, 2005
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
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
#include <errno.h>
#include <trousers/tss.h>


#define print_error(a,b) \
	fprintf(stderr, "%s:%d %s result: 0x%x", __FILE__, __LINE__, a, b)

/* TODO:
 * - add command line options for all key attributes
 *
 */

TSS_UUID SRK_UUID = TSS_UUID_SRK;

int main(int argc, char **argv)
{
	TSS_HCONTEXT	hContext;
	TSS_FLAG	initFlags;
	TSS_HKEY	hKey;
	TSS_HKEY	hSRK;
	TSS_RESULT	result;
	TSS_HPOLICY	srkUsagePolicy, keyUsagePolicy, keyMigPolicy;
	BYTE		*blob;
	UINT32		blob_size;
	FILE		*out;
	char		*filename;


	initFlags	= TSS_KEY_TYPE_LEGACY | TSS_KEY_SIZE_2048  |
			TSS_KEY_VOLATILE | TSS_KEY_NO_AUTHORIZATION |
			TSS_KEY_NOT_MIGRATABLE;

	if (argc != 2) {
		fprintf(stderr, "need filename\n");
		exit(1);
	} else {
		filename = argv[1];
	}

		//Create Context
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create", result);
		exit(result);
	}
		//Connect Context
	result = Tspi_Context_Connect(hContext, NULL);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Create Object
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
					   initFlags, &hKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	if ((result = Tspi_SetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
					   TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
					   TSS_SS_RSASSAPKCS1V15_DER))) {
		print_error("Tspi_SetAttribUint32", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	if ((result = Tspi_SetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
					   TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
					   TSS_ES_RSAESPKCSV15))) {
		print_error("Tspi_SetAttribUint32", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Load Key By UUID
	result = Tspi_Context_LoadKeyByUUID(hContext,
					    TSS_PS_TYPE_SYSTEM, SRK_UUID,
					    &hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Get Policy Object
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &srkUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Set Secret
	result = Tspi_Policy_SetSecret(srkUsagePolicy, TSS_SECRET_MODE_PLAIN,
				0, NULL);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
#if 0
		//Get Policy Object
	result = Tspi_GetPolicyObject(hKey, TSS_POLICY_USAGE, &keyUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Set Secret
	result = Tspi_Policy_SetSecret(keyUsagePolicy, TSS_SECRET_MODE_PLAIN,
				0, NULL);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
#endif
		//Create Key
	result = Tspi_Key_CreateKey(hKey, hSRK, 0);
	if (result != TSS_SUCCESS){
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
