/* ====================================================================
 * Copyright (c) 2004 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

/*
 * (C) COPYRIGHT International Business Machines Corp. 2004, 2005
 *
 * Kent Yoder <yoder1@us.ibm.com>
 *
 */

#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/dso.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/bn.h>

#include <tss/platform.h>
#include <tss/tcpa_defines.h>
#include <tss/tcpa_typedef.h>
#include <tss/tcpa_struct.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tss_error.h>
#include <tss/tspi.h>

#include <trousers/trousers.h>  // XXX DEBUG

#include "e_tpm.h"

#ifndef OPENSSL_NO_HW
#ifndef OPENSSL_NO_HW_TPM

/* Tspi library functions */
static const char *TPM_F_Context_Create = "Tspi_Context_Create";
static const char *TPM_F_Context_Close = "Tspi_Context_Close";
static const char *TPM_F_Context_Connect = "Tspi_Context_Connect";
static const char *TPM_F_Context_CreateObject = "Tspi_Context_CreateObject";
static const char *TPM_F_Context_CloseObject = "Tspi_Context_CloseObject";
static const char *TPM_F_Context_FreeMemory = "Tspi_Context_FreeMemory";
static const char *TPM_F_Context_LoadKeyByBlob = "Tspi_Context_LoadKeyByBlob";
static const char *TPM_F_Context_LoadKeyByUUID = "Tspi_Context_LoadKeyByUUID";
static const char *TPM_F_Context_GetTpmObject = "Tspi_Context_GetTpmObject";
static const char *TPM_F_TPM_GetRandom = "Tspi_TPM_GetRandom";
static const char *TPM_F_TPM_StirRandom = "Tspi_TPM_StirRandom";
static const char *TPM_F_Key_CreateKey = "Tspi_Key_CreateKey";
static const char *TPM_F_Key_LoadKey = "Tspi_Key_LoadKey";
static const char *TPM_F_Data_Bind = "Tspi_Data_Bind";
static const char *TPM_F_Data_Unbind = "Tspi_Data_Unbind";
static const char *TPM_F_GetAttribData = "Tspi_GetAttribData";
static const char *TPM_F_SetAttribData = "Tspi_SetAttribData";
static const char *TPM_F_GetAttribUint32 = "Tspi_GetAttribUint32";
static const char *TPM_F_SetAttribUint32 = "Tspi_SetAttribUint32";
static const char *TPM_F_GetPolicyObject = "Tspi_GetPolicyObject";
static const char *TPM_F_Hash_Sign = "Tspi_Hash_Sign";
static const char *TPM_F_Hash_SetHashValue = "Tspi_Hash_SetHashValue";
static const char *TPM_F_Policy_SetSecret = "Tspi_Policy_SetSecret";

/* engine specific functions */
static int tpm_engine_destroy(ENGINE *);
static int tpm_engine_init(ENGINE *);
static int tpm_engine_finish(ENGINE *);
static int tpm_engine_ctrl(ENGINE *, int, long, void *, void (*)());
static EVP_PKEY *tpm_engine_load_key(ENGINE *, const char *, UI_METHOD *, void *);
static char *tpm_engine_get_auth(UI_METHOD *, char *, int, char *);

#ifndef OPENSSL_NO_RSA
/* rsa functions */
static int tpm_rsa_init(RSA *rsa);
static int tpm_rsa_finish(RSA *rsa);
static int tpm_rsa_pub_dec(int, const unsigned char *, unsigned char *, RSA *, int);
static int tpm_rsa_pub_enc(int, const unsigned char *, unsigned char *, RSA *, int);
static int tpm_rsa_priv_dec(int, const unsigned char *, unsigned char *, RSA *, int);
static int tpm_rsa_priv_enc(int, const unsigned char *, unsigned char *, RSA *, int);
//static int tpm_rsa_sign(int, const unsigned char *, unsigned int, unsigned char *, unsigned int *, const RSA *);
static int tpm_rsa_keygen(RSA *, int, BIGNUM *, BN_GENCB *);
#endif

/* random functions */
static int tpm_rand_bytes(unsigned char *, int);
static int tpm_rand_status(void);
static void tpm_rand_seed(const void *, int);

static TSS_UUID SRK_UUID = TSS_UUID_SRK;

/* The definitions for control commands specific to this engine */
#define TPM_CMD_SO_PATH		ENGINE_CMD_BASE
static const ENGINE_CMD_DEFN tpm_cmd_defns[] = {
	{TPM_CMD_SO_PATH,
	 "SO_PATH",
	 "Specifies the path to the libtspi.so shared library",
	 ENGINE_CMD_FLAG_STRING},
	{0, NULL, NULL, 0}
};

#ifndef OPENSSL_NO_RSA
static RSA_METHOD tpm_rsa = {
	"TPM RSA method",
	tpm_rsa_pub_enc,
	tpm_rsa_pub_dec,
	tpm_rsa_priv_enc,
	tpm_rsa_priv_dec,
	NULL,
	NULL,
	tpm_rsa_init,
	tpm_rsa_finish,
	(RSA_FLAG_SIGN_VER | RSA_FLAG_NO_BLINDING),
	NULL,
	NULL, /* sign */
	NULL, /* verify */
	tpm_rsa_keygen
};
#endif

static RAND_METHOD tpm_rand = {
	/* "TPM RAND method", */
	tpm_rand_seed,
	tpm_rand_bytes,
	NULL,
	NULL,
	tpm_rand_bytes,
	tpm_rand_status,
};

/* Constants used when creating the ENGINE */
static const char *engine_tpm_id = "tpm";
static const char *engine_tpm_name = "TPM hardware engine support";
static const char *TPM_LIBNAME = "tspi";

static TSS_HCONTEXT hContext = NULL_HCONTEXT;
static TSS_HKEY     hSRK     = NULL_HKEY;
static TSS_HTPM     hTPM     = NULL_HTPM;

/* varibles used to get/set CRYPTO_EX_DATA values */
int  ex_app_data = TPM_ENGINE_EX_DATA_UNINIT;

/* This is a process-global DSO handle used for loading and unloading
 * the TSS library. NB: This is only set (or unset) during an
 * init() or finish() call (reference counts permitting) and they're
 * operating with global locks, so this should be thread-safe
 * implicitly. */

static DSO *tpm_dso = NULL;

/* These are the function pointers that are (un)set when the library has
 * successfully (un)loaded. */
static unsigned int (*p_tspi_Context_Create)();
static unsigned int (*p_tspi_Context_Close)();
static unsigned int (*p_tspi_Context_Connect)();
static unsigned int (*p_tspi_Context_FreeMemory)();
static unsigned int (*p_tspi_Context_CreateObject)();
static unsigned int (*p_tspi_Context_LoadKeyByUUID)();
static unsigned int (*p_tspi_Context_LoadKeyByBlob)();
static unsigned int (*p_tspi_Context_GetTpmObject)();
static unsigned int (*p_tspi_TPM_GetRandom)();
static unsigned int (*p_tspi_TPM_StirRandom)();
static unsigned int (*p_tspi_Key_CreateKey)();
static unsigned int (*p_tspi_Key_LoadKey)();
static unsigned int (*p_tspi_Data_Bind)();
static unsigned int (*p_tspi_Data_Unbind)();
static unsigned int (*p_tspi_GetAttribData)();
static unsigned int (*p_tspi_SetAttribData)();
static unsigned int (*p_tspi_SetAttribUint32)();
static unsigned int (*p_tspi_GetAttribUint32)();
static unsigned int (*p_tspi_Context_CloseObject)();
static unsigned int (*p_tspi_Hash_Sign)();
static unsigned int (*p_tspi_Hash_SetHashValue)();
static unsigned int (*p_tspi_GetPolicyObject)();
static unsigned int (*p_tspi_Policy_SetSecret)();

/* This internal function is used by ENGINE_tpm() and possibly by the
 * "dynamic" ENGINE support too */
static int bind_helper(ENGINE * e)
{
	if (!ENGINE_set_id(e, engine_tpm_id) ||
	    !ENGINE_set_name(e, engine_tpm_name) ||
#ifndef OPENSSL_NO_RSA
	    !ENGINE_set_RSA(e, &tpm_rsa) ||
#endif
	    !ENGINE_set_RAND(e, &tpm_rand) ||
	    !ENGINE_set_destroy_function(e, tpm_engine_destroy) ||
	    !ENGINE_set_init_function(e, tpm_engine_init) ||
	    !ENGINE_set_finish_function(e, tpm_engine_finish) ||
	    !ENGINE_set_ctrl_function(e, tpm_engine_ctrl) ||
	    !ENGINE_set_load_pubkey_function(e, tpm_engine_load_key) ||
	    !ENGINE_set_load_privkey_function(e, tpm_engine_load_key) ||
	    !ENGINE_set_cmd_defns(e, tpm_cmd_defns))
		return 0;

	/* Ensure the tpm error handling is set up */
	ERR_load_TPM_strings();
	return 1;
}

static ENGINE *engine_tpm(void)
{
	ENGINE *ret = ENGINE_new();
	DBG("%s", __FUNCTION__);
	if (!ret)
		return NULL;
	if (!bind_helper(ret)) {
		ENGINE_free(ret);
		return NULL;
	}
	return ret;
}

void ENGINE_load_tpm(void)
{
	/* Copied from eng_[openssl|dyn].c */
	ENGINE *toadd = engine_tpm();
	if (!toadd)
		return;
	ENGINE_add(toadd);
	ENGINE_free(toadd);
	ERR_clear_error();
}

int tpm_load_srk(UI_METHOD *ui)
{
	TSS_RESULT result;
	TSS_HPOLICY hPolicy;
	BYTE *auth;

	if (hSRK != NULL_HKEY)
		return 1;

	if ((result = p_tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM,
						   SRK_UUID, &hSRK))) {
		TSSerr(TPM_F_TPM_LOAD_SRK, TPM_R_REQUEST_FAILED);
		return 0;
	}

	if ((result = p_tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE,
					     &hPolicy))) {
		p_tspi_Context_CloseObject(hContext, hSRK);
		TSSerr(TPM_F_TPM_LOAD_SRK, TPM_R_REQUEST_FAILED);
		return 0;
	}

	if ((auth = calloc(1, 128)) == NULL) {
		TSSerr(TPM_F_TPM_LOAD_SRK, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	if (!tpm_engine_get_auth(ui, auth, 128, "SRK authorization: ")) {
		p_tspi_Context_CloseObject(hContext, hSRK);
		free(auth);
		TSSerr(TPM_F_TPM_LOAD_SRK, TPM_R_REQUEST_FAILED);
	}

	if ((result = p_tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_PLAIN,
					      strlen(auth), auth))) {
		p_tspi_Context_CloseObject(hContext, hSRK);
		p_tspi_Context_CloseObject(hContext, hPolicy);
		free(auth);
		TSSerr(TPM_F_TPM_LOAD_SRK, TPM_R_REQUEST_FAILED);
		return 0;
	}

	free(auth);

	return 1;
}

/* Destructor (complements the "ENGINE_tpm()" constructor) */
static int tpm_engine_destroy(ENGINE * e)
{
	/* Unload the tpm error strings so any error state including our
	 * functs or reasons won't lead to a segfault (they simply get displayed
	 * without corresponding string data because none will be found). */
	ERR_unload_TPM_strings();
	return 1;
}

/* initialisation function */
static int tpm_engine_init(ENGINE * e)
{
	void (*p1) ();
	void (*p2) ();
	void (*p3) ();
	void (*p4) ();
	void (*p5) ();
	void (*p6) ();
	void (*p7) ();
	void (*p8) ();
	void (*p9) ();
	void (*p10) ();
	void (*p11) ();
	void (*p12) ();
	void (*p13) ();
	void (*p14) ();
	void (*p15) ();
	void (*p16) ();
	void (*p17) ();
	void (*p18) ();
	void (*p19) ();
	void (*p20) ();
	void (*p21) ();
	void (*p22) ();
	void (*p23) ();
	TSS_RESULT result;

	DBG("%s", __FUNCTION__);

	if (tpm_dso != NULL) {
		TSSerr(TPM_F_TPM_ENGINE_INIT, TPM_R_ALREADY_LOADED);
		goto err;
	}

	if ((tpm_dso = DSO_load(NULL, TPM_LIBNAME, NULL, 0)) == NULL) {
		TSSerr(TPM_F_TPM_ENGINE_INIT, TPM_R_DSO_FAILURE);
		goto err;
	}

	if (!(p1  = DSO_bind_func(tpm_dso, TPM_F_Context_Create)) ||
	    !(p2  = DSO_bind_func(tpm_dso, TPM_F_Context_Close)) ||
	    !(p3  = DSO_bind_func(tpm_dso, TPM_F_Context_Connect)) ||
	    !(p4  = DSO_bind_func(tpm_dso, TPM_F_TPM_GetRandom)) ||
	    !(p5  = DSO_bind_func(tpm_dso, TPM_F_Key_CreateKey)) ||
	    !(p6  = DSO_bind_func(tpm_dso, TPM_F_Data_Bind)) ||
	    !(p7  = DSO_bind_func(tpm_dso, TPM_F_Data_Unbind)) ||
	    !(p8  = DSO_bind_func(tpm_dso, TPM_F_Context_CreateObject)) ||
	    !(p9  = DSO_bind_func(tpm_dso, TPM_F_Context_FreeMemory)) ||
	    !(p10 = DSO_bind_func(tpm_dso, TPM_F_Key_LoadKey)) ||
	    !(p11 = DSO_bind_func(tpm_dso, TPM_F_Context_LoadKeyByUUID)) ||
	    !(p12 = DSO_bind_func(tpm_dso, TPM_F_GetAttribData)) ||
	    !(p13 = DSO_bind_func(tpm_dso, TPM_F_Hash_Sign)) ||
	    !(p14 = DSO_bind_func(tpm_dso, TPM_F_Context_CloseObject)) ||
	    !(p15 = DSO_bind_func(tpm_dso, TPM_F_Hash_SetHashValue)) ||
	    !(p16 = DSO_bind_func(tpm_dso, TPM_F_SetAttribUint32)) ||
	    !(p17 = DSO_bind_func(tpm_dso, TPM_F_GetPolicyObject)) ||
	    !(p18 = DSO_bind_func(tpm_dso, TPM_F_Policy_SetSecret)) ||
	    !(p19 = DSO_bind_func(tpm_dso, TPM_F_TPM_StirRandom)) ||
	    !(p20 = DSO_bind_func(tpm_dso, TPM_F_Context_LoadKeyByBlob)) ||
	    !(p21 = DSO_bind_func(tpm_dso, TPM_F_Context_GetTpmObject)) ||
	    !(p22 = DSO_bind_func(tpm_dso, TPM_F_GetAttribUint32)) ||
	    !(p23 = DSO_bind_func(tpm_dso, TPM_F_SetAttribData))
	    ) {
		TSSerr(TPM_F_TPM_ENGINE_INIT, TPM_R_DSO_FAILURE);
		goto err;
	}

	/* Copy the pointers */
	p_tspi_Context_Create = (unsigned int (*) ()) p1;
	p_tspi_Context_Close = (unsigned int (*) ()) p2;
	p_tspi_Context_Connect = (unsigned int (*) ()) p3;
	p_tspi_TPM_GetRandom = (unsigned int (*) ()) p4;
	p_tspi_Key_CreateKey = (unsigned int (*) ()) p5;
	p_tspi_Data_Bind = (unsigned int (*) ()) p6;
	p_tspi_Data_Unbind = (unsigned int (*) ()) p7;
	p_tspi_Context_CreateObject = (unsigned int (*) ()) p8;
	p_tspi_Context_FreeMemory = (unsigned int (*) ()) p9;
	p_tspi_Key_LoadKey = (unsigned int (*) ()) p10;
	p_tspi_Context_LoadKeyByUUID = (unsigned int (*) ()) p11;
	p_tspi_GetAttribData = (unsigned int (*) ()) p12;
	p_tspi_Hash_Sign = (unsigned int (*) ()) p13;
	p_tspi_Context_CloseObject = (unsigned int (*) ()) p14;
	p_tspi_Hash_SetHashValue = (unsigned int (*) ()) p15;
	p_tspi_SetAttribUint32 = (unsigned int (*) ()) p16;
	p_tspi_GetPolicyObject = (unsigned int (*) ()) p17;
	p_tspi_Policy_SetSecret = (unsigned int (*) ()) p18;
	p_tspi_TPM_StirRandom = (unsigned int (*) ()) p19;
	p_tspi_Context_LoadKeyByBlob = (unsigned int (*) ()) p20;
	p_tspi_Context_GetTpmObject = (unsigned int (*) ()) p21;
	p_tspi_GetAttribUint32 = (unsigned int (*) ()) p22;
	p_tspi_SetAttribData = (unsigned int (*) ()) p23;

	if ((result = p_tspi_Context_Create(&hContext))) {
		TSSerr(TPM_F_TPM_ENGINE_INIT, TPM_R_UNIT_FAILURE);
		goto err;
	}

	/* XXX allow dest to be specified through pre commands */
	if ((result = p_tspi_Context_Connect(hContext, NULL))) {
		TSSerr(TPM_F_TPM_ENGINE_INIT, TPM_R_UNIT_FAILURE);
		goto err;
	}

	if ((result = p_tspi_Context_GetTpmObject(hContext, &hTPM))) {
		TSSerr(TPM_F_TPM_ENGINE_INIT, TPM_R_UNIT_FAILURE);
		goto err;
	}

	return 1;
err:
	if (hContext != NULL_HCONTEXT) {
		p_tspi_Context_Close(hContext);
		hContext = NULL_HCONTEXT;
		hTPM = NULL_HTPM;
	}

	if (tpm_dso) {
		DSO_free(tpm_dso);
		tpm_dso = NULL;
	}

	p_tspi_Context_Create = NULL;
	p_tspi_Context_Close = NULL;
	p_tspi_Context_Connect = NULL;
	p_tspi_Context_FreeMemory = NULL;
	p_tspi_Context_LoadKeyByBlob = NULL;
	p_tspi_Context_LoadKeyByUUID = NULL;
	p_tspi_Context_GetTpmObject = NULL;
	p_tspi_Context_CloseObject = NULL;
	p_tspi_Key_CreateKey = NULL;
	p_tspi_Key_LoadKey = NULL;
	p_tspi_Data_Bind = NULL;
	p_tspi_Data_Unbind = NULL;
	p_tspi_Hash_SetHashValue = NULL;
	p_tspi_Hash_Sign = NULL;
	p_tspi_GetAttribData = NULL;
	p_tspi_SetAttribData = NULL;
	p_tspi_GetAttribUint32 = NULL;
	p_tspi_SetAttribUint32 = NULL;
	p_tspi_GetPolicyObject = NULL;
	p_tspi_Policy_SetSecret = NULL;
	p_tspi_TPM_StirRandom = NULL;
	p_tspi_TPM_GetRandom = NULL;

	return 0;
}

static char *tpm_engine_get_auth(UI_METHOD *ui_method, char *auth, int maxlen,
				 char *input_string)
{
	UI *ui;

	DBG("%s", __FUNCTION__);

	ui = UI_new();
	if (ui_method)
		UI_set_method(ui, ui_method);

	if (!UI_add_input_string(ui, input_string, 0, auth, 0, maxlen)) {
		TSSerr(TPM_F_TPM_ENGINE_GET_AUTH, TPM_R_UI_METHOD_FAILED);
		UI_free(ui);
		return NULL;
	}

	if (UI_process(ui)) {
		TSSerr(TPM_F_TPM_ENGINE_GET_AUTH, TPM_R_UI_METHOD_FAILED);
		UI_free(ui);
		return NULL;
	}

	UI_free(ui);
	return auth;
}

static int tpm_engine_finish(ENGINE * e)
{
	DBG("%s", __FUNCTION__);

	if (tpm_dso == NULL) {
		TSSerr(TPM_F_TPM_ENGINE_FINISH, TPM_R_NOT_LOADED);
		return 0;
	}

	if (hContext != NULL_HCONTEXT) {
		p_tspi_Context_Close(hContext);
		hContext = NULL_HCONTEXT;
	}

	if (!DSO_free(tpm_dso)) {
		TSSerr(TPM_F_TPM_ENGINE_FINISH, TPM_R_DSO_FAILURE);
		return 0;
	}
	tpm_dso = NULL;

	return 1;
}

int fill_out_rsa_object(RSA *rsa, TSS_HKEY hKey)
{
	TSS_RESULT result;
	UINT32 pubkey_len, encScheme, sigScheme;
	BYTE *pubkey;
	struct rsa_app_data *app_data;

	DBG("%s", __FUNCTION__);

	if ((result = p_tspi_GetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
					     TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
					     &encScheme))) {
		TSSerr(TPM_F_TPM_FILL_RSA_OBJECT, TPM_R_REQUEST_FAILED);
		return 0;
	}

	if ((result = p_tspi_GetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
					     TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
					     &sigScheme))) {
		TSSerr(TPM_F_TPM_FILL_RSA_OBJECT, TPM_R_REQUEST_FAILED);
		return 0;
	}

	/* pull out the public key and put it into the RSA object */
	if ((result = p_tspi_GetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB,
					   TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
					   &pubkey_len, &pubkey))) {
		TSSerr(TPM_F_TPM_FILL_RSA_OBJECT, TPM_R_REQUEST_FAILED);
		return 0;
	}

	if ((rsa->n = BN_bin2bn(pubkey, pubkey_len, rsa->n)) == NULL) {
		p_tspi_Context_FreeMemory(hContext, pubkey);
		TSSerr(TPM_F_TPM_FILL_RSA_OBJECT, TPM_R_BN_CONVERSION_FAILED);
		return 0;
	}

	p_tspi_Context_FreeMemory(hContext, pubkey);

	/* set e in the RSA object */
	if (!rsa->e && ((rsa->e = BN_new()) == NULL)) {
		TSSerr(TPM_F_TPM_FILL_RSA_OBJECT, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	if (!BN_set_word(rsa->e, 65537)) {
		TSSerr(TPM_F_TPM_FILL_RSA_OBJECT, TPM_R_REQUEST_FAILED);
		BN_free(rsa->e);
		rsa->e = NULL;
		return 0;
	}

	if ((app_data = OPENSSL_malloc(sizeof(struct rsa_app_data))) == NULL) {
		TSSerr(TPM_F_TPM_FILL_RSA_OBJECT, ERR_R_MALLOC_FAILURE);
		BN_free(rsa->e);
		rsa->e = NULL;
		return 0;
	}

	DBG("Setting hKey(0x%x) in RSA object", hKey);
	DBG("Setting encScheme(0x%x) in RSA object", encScheme);
	DBG("Setting sigScheme(0x%x) in RSA object", sigScheme);

	memset(app_data, 0, sizeof(struct rsa_app_data));
	app_data->hKey = hKey;
	app_data->encScheme = encScheme;
	app_data->sigScheme = sigScheme;
	RSA_set_ex_data(rsa, ex_app_data, app_data);

	return 1;
}

static EVP_PKEY *tpm_engine_load_key(ENGINE *e, const char *key_id,
				     UI_METHOD *ui, void *cb_data)
{
	TSS_HKEY hKey;
	TSS_RESULT result;
	BYTE blob_buf[4096];
	UINT32 authusage;
	RSA *rsa;
	EVP_PKEY *pkey;
	BIO *bf;
	int rc;


	DBG("%s", __FUNCTION__);

	if (!key_id) {
		TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}

	if (!tpm_load_srk(ui)) {
		TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, TPM_R_SRK_LOAD_FAILED);
		return NULL;
	}

	if ((bf = BIO_new_file(key_id, "r")) == NULL) {
		TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY,
		       TPM_R_FILE_NOT_FOUND);
		return NULL;
	}
retry:
	if ((rc = BIO_read(bf, &blob_buf[0], 4096)) < 0) {
		TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY,
		       TPM_R_FILE_READ_FAILED);
		return NULL;
	} else if (rc == 0 && BIO_should_retry(bf)) {
		goto retry;
	}

	DBG("Loading blob of size: %d", rc);
	if ((result = p_tspi_Context_LoadKeyByBlob(hContext, hSRK, rc,
					blob_buf, &hKey))) {
		TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY,
		       TPM_R_REQUEST_FAILED);
		return NULL;
	}

	if ((result = p_tspi_GetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
					     TSS_TSPATTRIB_KEYINFO_AUTHUSAGE,
					     &authusage))) {
		p_tspi_Context_CloseObject(hContext, hKey);
		TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY,
		       TPM_R_REQUEST_FAILED);
		return NULL;
	}

	if (authusage) {
		TSS_HPOLICY hPolicy;
		BYTE *auth;

		if ((auth = calloc(1, 128)) == NULL) {
			p_tspi_Context_CloseObject(hContext, hKey);
			TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, ERR_R_MALLOC_FAILURE);
			return NULL;
		}

		if (!tpm_engine_get_auth(ui, auth, 128,
					 "TPM Key Password: ")) {
			p_tspi_Context_CloseObject(hContext, hKey);
			free(auth);
			TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, TPM_R_REQUEST_FAILED);
			return NULL;
		}

		if ((result = p_tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE,
						     &hPolicy))) {
			p_tspi_Context_CloseObject(hContext, hKey);
			free(auth);
			TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, TPM_R_REQUEST_FAILED);
			return 0;
		}

		if ((result = p_tspi_Policy_SetSecret(hPolicy,
						      TSS_SECRET_MODE_PLAIN,
						      strlen(auth), auth))) {
			p_tspi_Context_CloseObject(hContext, hKey);
			free(auth);
			TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, TPM_R_REQUEST_FAILED);
			return 0;
		}

		free(auth);
	}

	/* create the new objects to return */
	if ((pkey = EVP_PKEY_new()) == NULL) {
		p_tspi_Context_CloseObject(hContext, hKey);
		TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	pkey->type = EVP_PKEY_RSA;

	if ((rsa = RSA_new()) == NULL) {
		EVP_PKEY_free(pkey);
		p_tspi_Context_CloseObject(hContext, hKey);
		TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	rsa->meth = &tpm_rsa;
	/* call our local init function here */
	rsa->meth->init(rsa);
	pkey->pkey.rsa = rsa;

	if (!fill_out_rsa_object(rsa, hKey)) {
		EVP_PKEY_free(pkey);
		RSA_free(rsa);
		p_tspi_Context_CloseObject(hContext, hKey);
		TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, TPM_R_REQUEST_FAILED);
		return NULL;
	}

	return pkey;
}

static int tpm_engine_ctrl(ENGINE * e, int cmd, long i, void *p, void (*f) ())
{
	int initialised = ((tpm_dso == NULL) ? 0 : 1);
	DBG("%s", __FUNCTION__);

	switch (cmd) {
		case TPM_CMD_SO_PATH:
			if (p == NULL) {
				TSSerr(TPM_F_TPM_ENGINE_CTRL,
				       ERR_R_PASSED_NULL_PARAMETER);
				return 0;
			}
			if (initialised) {
				TSSerr(TPM_F_TPM_ENGINE_CTRL,
				       TPM_R_ALREADY_LOADED);
				return 0;
			}
			TPM_LIBNAME = (const char *) p;
			return 1;
		default:
			break;
	}
	TSSerr(TPM_F_TPM_ENGINE_CTRL, TPM_R_CTRL_COMMAND_NOT_IMPLEMENTED);

	return 0;
}

#ifndef OPENSSL_NO_RSA
static int tpm_rsa_init(RSA *rsa)
{
	DBG("%s", __FUNCTION__);

	if (ex_app_data == TPM_ENGINE_EX_DATA_UNINIT)
		ex_app_data = RSA_get_ex_new_index(0, NULL, NULL, NULL, NULL);

	if (ex_app_data == TPM_ENGINE_EX_DATA_UNINIT) {
		TSSerr(TPM_F_TPM_RSA_INIT, TPM_R_REQUEST_FAILED);
		return 0;
	}

	return 1;
}

static int tpm_rsa_finish(RSA *rsa)
{
	DBG("%s", __FUNCTION__);

	return 1;
}

static int tpm_rsa_pub_dec(int flen,
			   const unsigned char *from,
			   unsigned char *to,
			   RSA *rsa,
			   int padding)
{
	int rv;

	DBG("%s", __FUNCTION__);

	if ((rv =
	    RSA_PKCS1_SSLeay()->rsa_pub_dec(flen, from, to, rsa, padding)) != 1) {
		TSSerr(TPM_F_TPM_RSA_PUB_DEC, TPM_R_REQUEST_FAILED);
		return 0;
	}

	DBG("%s: called eay function internally", __FUNCTION__);

	return rv;
}

static int tpm_rsa_priv_dec(int flen,
			    const unsigned char *from,
			    unsigned char *to,
			    RSA *rsa,
			    int padding)
{
	struct rsa_app_data *app_data = RSA_get_ex_data(rsa, ex_app_data);
	TSS_RESULT result;
	UINT32 out_len, in_len;
	BYTE *out;

	DBG("%s", __FUNCTION__);

	if (!app_data) {
		TSSerr(TPM_F_TPM_RSA_PRIV_DEC, TPM_R_NO_APP_DATA);
		return 0;
	}

	if (app_data->hKey == NULL_HKEY) {
		TSSerr(TPM_F_TPM_RSA_PRIV_DEC, TPM_R_INVALID_KEY);
		return 0;
	}

	if (app_data->hEncData == NULL_HENCDATA) {
		if ((result = p_tspi_Context_CreateObject(hContext,
							  TSS_OBJECT_TYPE_ENCDATA,
							  TSS_ENCDATA_BIND,
							  &app_data->hEncData))) {
			TSSerr(TPM_F_TPM_RSA_PRIV_DEC, TPM_R_REQUEST_FAILED);
			return 0;
		}
	}

	if (padding == RSA_PKCS1_PADDING &&
	    app_data->encScheme != TSS_ES_RSAESPKCSV15) {
		TSSerr(TPM_F_TPM_RSA_PRIV_DEC,
		       TPM_R_INVALID_PADDING_TYPE);
		DBG("encScheme(0x%x) in RSA object", app_data->encScheme);
		return 0;
	} else if (padding == RSA_PKCS1_OAEP_PADDING &&
		   app_data->encScheme != TSS_ES_RSAESOAEP_SHA1_MGF1) {
		TSSerr(TPM_F_TPM_RSA_PRIV_DEC,
		       TPM_R_INVALID_PADDING_TYPE);
		DBG("encScheme(0x%x) in RSA object", app_data->encScheme);
		return 0;
	}

	in_len = flen;
	if ((result = p_tspi_SetAttribData(app_data->hEncData,
					   TSS_TSPATTRIB_ENCDATA_BLOB,
					   TSS_TSPATTRIB_ENCDATABLOB_BLOB,
					   in_len, from))) {
		TSSerr(TPM_F_TPM_RSA_PRIV_DEC, TPM_R_REQUEST_FAILED);
		return 0;
	}

	if ((result = p_tspi_Data_Unbind(app_data->hEncData, app_data->hKey,
				       &out_len, &out))) {
		TSSerr(TPM_F_TPM_RSA_PRIV_DEC, TPM_R_REQUEST_FAILED);
		return 0;
	}

	DBG("%s: writing out %d bytes as a signature", __FUNCTION__, out_len);

	memcpy(to, out, out_len);
	p_tspi_Context_FreeMemory(hContext, out);

	return out_len;
}

static int tpm_rsa_pub_enc(int flen,
			   const unsigned char *from,
			   unsigned char *to,
			   RSA *rsa,
			   int padding)
{
	struct rsa_app_data *app_data = RSA_get_ex_data(rsa, ex_app_data);
	TSS_RESULT result;
	UINT32 out_len, in_len;
	BYTE *out;

	DBG("%s", __FUNCTION__);

	if (!app_data) {
		TSSerr(TPM_F_TPM_RSA_PUB_ENC, TPM_R_NO_APP_DATA);
		return 0;
	}

	if (app_data->hKey == NULL_HKEY) {
		TSSerr(TPM_F_TPM_RSA_PUB_ENC, TPM_R_INVALID_KEY);
		return 0;
	}

	if (app_data->hEncData == NULL_HENCDATA) {
		if ((result = p_tspi_Context_CreateObject(hContext,
							  TSS_OBJECT_TYPE_ENCDATA,
							  TSS_ENCDATA_BIND,
							  &app_data->hEncData))) {
			TSSerr(TPM_F_TPM_RSA_PUB_ENC, TPM_R_REQUEST_FAILED);
			return 0;
		}
		DBG("Setting hEncData(0x%x) in RSA object", app_data->hEncData);
	}

	DBG("flen is %d", flen);

	if (padding == RSA_PKCS1_PADDING) {
		if (app_data->encScheme != TSS_ES_RSAESPKCSV15) {
			TSSerr(TPM_F_TPM_RSA_PUB_ENC,
			       TPM_R_INVALID_PADDING_TYPE);
			DBG("encScheme(0x%x) in RSA object",
			    app_data->encScheme);
			return 0;
		}


		if (flen > (RSA_size(rsa) - RSA_PKCS1_PADDING_SIZE)) {
			TSSerr(TPM_F_TPM_RSA_PUB_ENC,
			       RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
			return 0;
		}
	} else if (padding == RSA_PKCS1_OAEP_PADDING) {
		if (app_data->encScheme != TSS_ES_RSAESOAEP_SHA1_MGF1) {
			TSSerr(TPM_F_TPM_RSA_PUB_ENC,
			       TPM_R_INVALID_PADDING_TYPE);
			DBG("encScheme(0x%x) in RSA object",
			    app_data->encScheme);
			return 0;
		}

		/* subtract an extra 5 for the TCPA_BOUND_DATA structure */
		if (flen > (RSA_size(rsa) - RSA_PKCS1_PADDING_SIZE - 5)) {
			TSSerr(TPM_F_TPM_RSA_PUB_ENC,
			       RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
			return 0;
		}
	} else {
		TSSerr(TPM_F_TPM_RSA_PUB_ENC, TPM_R_INVALID_ENC_SCHEME);
		return 0;
	}

	in_len = flen;
	DBG("Bind: hKey(0x%x) hEncData(0x%x) in_len(%u)", app_data->hKey,
	    app_data->hEncData, in_len);

	if ((result = p_tspi_Data_Bind(app_data->hEncData, app_data->hKey,
				       in_len, from))) {
		TSSerr(TPM_F_TPM_RSA_PUB_ENC, TPM_R_REQUEST_FAILED);
		DBG("result = 0x%x (%s)", result,
		    Trspi_Error_String(result));
		return 0;
	}

	/* pull out the bound data and return it */
	if ((result = p_tspi_GetAttribData(app_data->hEncData,
					   TSS_TSPATTRIB_ENCDATA_BLOB,
					   TSS_TSPATTRIB_ENCDATABLOB_BLOB,
					   &out_len, &out))) {
		TSSerr(TPM_F_TPM_RSA_KEYGEN, TPM_R_REQUEST_FAILED);
		return 0;
	}

	DBG("%s: writing out %d bytes as bound data", __FUNCTION__, out_len);

	memcpy(to, out, out_len);
	p_tspi_Context_FreeMemory(hContext, out);

	return out_len;
}

static int tpm_rsa_priv_enc(int flen,
			    const unsigned char *from,
			    unsigned char *to,
			    RSA *rsa,
			    int padding)
{
	struct rsa_app_data *app_data = RSA_get_ex_data(rsa, ex_app_data);
	TSS_RESULT result;
	UINT32 sig_len;
	BYTE *sig;

	DBG("%s", __FUNCTION__);

	if (!app_data) {
		TSSerr(TPM_F_TPM_RSA_PRIV_ENC, TPM_R_NO_APP_DATA);
		return 0;
	}

	if (padding != RSA_PKCS1_PADDING) {
		TSSerr(TPM_F_TPM_RSA_PRIV_ENC, TPM_R_INVALID_PADDING_TYPE);
		return 0;
	}

	if (app_data->hKey == NULL_HKEY) {
		TSSerr(TPM_F_TPM_RSA_PRIV_ENC, TPM_R_INVALID_KEY);
		return 0;
	}

	if (app_data->hHash == NULL_HHASH) {
		if ((result = p_tspi_Context_CreateObject(hContext,
							  TSS_OBJECT_TYPE_HASH,
							  TSS_HASH_OTHER,
							  &app_data->hHash))) {
			TSSerr(TPM_F_TPM_RSA_PRIV_ENC, TPM_R_REQUEST_FAILED);
			return 0;
		}
	}

	if (app_data->sigScheme == TSS_SS_RSASSAPKCS1V15_SHA1) {
		if (flen != SHA_DIGEST_LENGTH) {
			TSSerr(TPM_F_TPM_RSA_PRIV_ENC, TPM_R_INVALID_MSG_SIZE);
			return 0;
		}
	} else if (app_data->sigScheme == TSS_SS_RSASSAPKCS1V15_DER) {
		if (flen > (RSA_size(rsa) - RSA_PKCS1_PADDING_SIZE)) {
			TSSerr(TPM_F_TPM_RSA_PRIV_ENC, TPM_R_INVALID_MSG_SIZE);
			return 0;
		}
	} else {
		TSSerr(TPM_F_TPM_RSA_PRIV_ENC, TPM_R_INVALID_ENC_SCHEME);
		return 0;
	}

	if ((result = p_tspi_Hash_SetHashValue(app_data->hHash, flen, from))) {
		TSSerr(TPM_F_TPM_RSA_PRIV_ENC, TPM_R_REQUEST_FAILED);
		return 0;
	}

	if ((result = p_tspi_Hash_Sign(app_data->hHash, app_data->hKey,
				       &sig_len, &sig))) {
		TSSerr(TPM_F_TPM_RSA_PRIV_ENC, TPM_R_REQUEST_FAILED);
		DBG("result = 0x%x (%s)", result,
		    Trspi_Error_String(result));
		return 0;
	}

	DBG("%s: writing out %d bytes as a signature", __FUNCTION__, sig_len);

	memcpy(to, sig, sig_len);
	p_tspi_Context_FreeMemory(hContext, sig);

	return sig_len;
}

/* create a new key.  we need a way to specify creation of a key with OAEP
 * padding as well as PKCSv1.5, since signatures will need to be done on
 * data larger than 20 bytes, which is the max size *regardless of key size*
 * for an OAEP key signing using the TPM */
static int tpm_rsa_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
	TSS_RESULT result;
	TSS_FLAG initFlags = TSS_KEY_TYPE_LEGACY;
	UINT32 encScheme, sigScheme;
	TSS_HKEY hKey;

	/* XXX allow this to be specified through pre commands */
	sigScheme = TSS_SS_RSASSAPKCS1V15_DER;
	encScheme = TSS_ES_RSAESPKCSV15;

	DBG("%s", __FUNCTION__);

	if (!BN_is_word(e, 65537)) {
		TSSerr(TPM_F_TPM_RSA_KEYGEN, TPM_R_INVALID_EXPONENT);
		return 0;
	}

	/* set e in the RSA object as done in the built-in openssl function */
	if (!rsa->e && ((rsa->e = BN_new()) == NULL)) {
		TSSerr(TPM_F_TPM_RSA_KEYGEN, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	BN_copy(rsa->e, e);

	switch (bits) {
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
			TSSerr(TPM_F_TPM_RSA_KEYGEN, TPM_R_INVALID_KEY_SIZE);
			return 0;
	}

	/* Load the parent key (SRK) which will wrap the new key */
	if (!tpm_load_srk(NULL)) {
		TSSerr(TPM_F_TPM_RSA_KEYGEN, TPM_R_SRK_LOAD_FAILED);
		return 0;
	}

	/* Create the new key object */
	if ((result = p_tspi_Context_CreateObject(hContext,
						  TSS_OBJECT_TYPE_RSAKEY,
						  initFlags, &hKey))) {
		TSSerr(TPM_F_TPM_RSA_KEYGEN, TPM_R_REQUEST_FAILED);
		return 0;
	}

	/* set the signature scheme */
	if ((result = p_tspi_SetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
					     TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
					     sigScheme))) {
		p_tspi_Context_CloseObject(hContext, hKey);
		TSSerr(TPM_F_TPM_RSA_KEYGEN, TPM_R_REQUEST_FAILED);
		return 0;
	}

	/* set the encryption scheme */
	if ((result = p_tspi_SetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
					     TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
					     encScheme))) {
		p_tspi_Context_CloseObject(hContext, hKey);
		TSSerr(TPM_F_TPM_RSA_KEYGEN, TPM_R_REQUEST_FAILED);
		return 0;
	}

	/* Call create key using the new object */
	if ((result = p_tspi_Key_CreateKey(hKey, hSRK, NULL))) {
		p_tspi_Context_CloseObject(hContext, hKey);
		TSSerr(TPM_F_TPM_RSA_KEYGEN, TPM_R_REQUEST_FAILED);
		return 0;
	}

	if (!fill_out_rsa_object(rsa, hKey)) {
		p_tspi_Context_CloseObject(hContext, hKey);
		TSSerr(TPM_F_TPM_RSA_KEYGEN, TPM_R_REQUEST_FAILED);
		return 0;
	}

	return 1;
}
#endif

static int tpm_rand_bytes(unsigned char *buf, int num)
{
	TSS_RESULT result;
	BYTE *rand_data;

	DBG("%s getting %d bytes", __FUNCTION__, num);

	if (num > 4096) {
		TSSerr(TPM_F_TPM_RAND_BYTES, TPM_R_REQUEST_TOO_BIG);
		return 0;
	}

	if ((result = p_tspi_TPM_GetRandom(hTPM, num, &rand_data))) {
		TSSerr(TPM_F_TPM_RAND_BYTES, TPM_R_REQUEST_FAILED);
		return 0;
	}

	memcpy(&buf[0], &rand_data[0], num);
	p_tspi_Context_FreeMemory(hContext, rand_data);

	return 1;
}

static int tpm_rand_status(void)
{
	DBG("%s", __FUNCTION__);
	return 1;
}

static void tpm_rand_seed(const void *buf, int num)
{
	TSS_RESULT result;
	DBG("%s", __FUNCTION__);

	if ((result = p_tspi_TPM_StirRandom(hTPM, (UINT32)num, buf))) {
		TSSerr(TPM_F_TPM_RAND_SEED, TPM_R_REQUEST_FAILED);
	}

	return;
}

/* This stuff is needed if this ENGINE is being compiled into a self-contained
 * shared-library. */
static int bind_fn(ENGINE * e, const char *id)
{
	if (id && (strcmp(id, engine_tpm_id) != 0)) {
		TSSerr(TPM_F_TPM_BIND_FN, TPM_R_ID_INVALID);
		return 0;
	}
	if (!bind_helper(e)) {
		TSSerr(TPM_F_TPM_BIND_FN, TPM_R_REQUEST_FAILED);
		return 0;
	}
	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
#endif
#endif
