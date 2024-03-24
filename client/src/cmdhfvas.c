//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// An implementation of the Value Added Service protocol
//-----------------------------------------------------------------------------

#include "cmdhfvas.h"
#include "cliparser.h"
#include "cmdparser.h"
#include "comms.h"
#include "ansi.h"
#include "cmdhf14a.h"
#include "emv/tlv.h"
#include "iso7816/apduinfo.h"
#include "ui.h"
#include "util.h"
#include "util_posix.h"
#include "iso7816/iso7816core.h"
#include <stddef.h>
#include <stdbool.h>
#include "mifare.h"
#include <stdlib.h>
#include <string.h>
#include "crypto/libpcrypto.h"
#include "fileutils.h"
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecc_point_compression.h"
#include "mbedtls/gcm.h"
#include <stdio.h>

#define SW_CODES_LEN 200

typedef struct {
    const char *tag;
    const char *description;
    const char *data_type;
    const char *category;
} TagInfo;

static TagInfo TAGS[] = {
    {"50", "Application Label", "TEXT", "ITEM"},
    {"6F", "File Control Information (FCI) Template", "BINARY", "TEMPLATE"},
    {"9F21", "Mobile Application Version", "BINARY", "ITEM"},
    {"9F21", "Transaction Time HHMMSS", "BINARY", "ITEM"},
    {"9F24", "Nonce", "BINARY", "ITEM"},
    {"9F22", "Protocol Version", "BINARY", "ITEM"},
    {"9F25", "SHA256 of Pass ID", "BINARY", "ITEM"},
    {"9F26", "Capabilities Mask", "BINARY", "ITEM"},
    {"9F29", "Merchant Signup URL", "BINARY", "ITEM"},
    {"9F2B", "Nonce", "BINARY", "ITEM"},
    {"9F28", "Nonce", "BINARY", "ITEM"}
};

const char *SW_CODES[SW_CODES_LEN][2] = {
    {"6200", "No information given (NV-Ram not changed)"},
    {"6201", "NV-Ram not changed 1."},
    {"6281", "Part of returned data may be corrupted"},
    {"6282", "End of file/record reached before reading Le bytes"},
    {"6283", "Selected file invalidated"},
    {"6284", "Selected file is not valid. FCI not formated according to ISO"},
    {"6285", "No input data available from a sensor on the card. No Purse Engine enslaved for R3bc"},
    {"62A2", "Wrong R-MAC"},
    {"62A4", "Card locked (during reset( ))"},
    {"62F1", "Wrong C-MAC"},
    {"62F3", "Internal reset"},
    {"62F5", "Default agent locked"},
    {"62F7", "Cardholder locked"},
    {"62F8", "Basement is current agent"},
    {"62F9", "CALC Key Set not unblocked"},
    {"6300", "No information given (NV-Ram changed)"},
    {"6381", "File filled up by the last write. Loading/updating is not allowed."},
    {"6382", "Card key not supported."},
    {"6383", "Reader key not supported."},
    {"6384", "Plaintext transmission not supported."},
    {"6385", "Secured transmission not supported."},
    {"6386", "Volatile memory is not available."},
    {"6387", "Non-volatile memory is not available."},
    {"6388", "Key number not valid."},
    {"6389", "Key length is not correct."},
    {"63C0", "Verify fail, no try left."},
    {"63C1", "Verify fail, 1 try left."},
    {"63C2", "Verify fail, 2 tries left."},
    {"63C3", "Verify fail, 3 tries left."},
    {"63F1", "More data expected."},
    {"63F2", "More data expected and proactive command pending."},
    {"6400", "No information given (NV-Ram not changed)"},
    {"6401", "Command timeout. Immediate response required by the card."},
    {"6500", "No information given"},
    {"6501", "Write error. Memory failure. There have been problems in writing or reading the EEPROM. Other hardware problems may also bring this error."},
    {"6581", "Memory failure"},
    {"6600", "Error while receiving (timeout)"},
    {"6601", "Error while receiving (character parity error)"},
    {"6602", "Wrong checksum"},
    {"6603", "The current DF file without FCI"},
    {"6604", "No SF or KF under the current DF"},
    {"6669", "Incorrect Encryption/Decryption Padding"},
    {"6700", "Wrong length"},
    {"6800", "No information given (The request function is not supported by the card)"},
    {"6881", "Logical channel not supported"},
    {"6882", "Secure messaging not supported"},
    {"6883", "Last command of the chain expected"},
    {"6884", "Command chaining not supported"},
    {"6900", "No information given (Command not allowed)"},
    {"6901", "Command not accepted (inactive state)"},
    {"6981", "Command incompatible with file structure"},
    {"6982", "Security condition not satisfied."},
    {"6983", "Authentication method blocked"},
    {"6984", "Referenced data reversibly blocked (invalidated)"},
    {"6985", "Conditions of use not satisfied."},
    {"6986", "Command not allowed (no current EF)"},
    {"6987", "Expected secure messaging (SM) object missing"},
    {"6988", "Incorrect secure messaging (SM) data object"},
    {"698D", "Reserved"},
    {"6996", "Data must be updated again"},
    {"69E1", "POL1 of the currently Enabled Profile prevents this action."},
    {"69F0", "Permission Denied"},
    {"69F1", "Permission Denied - Missing Privilege"},
    {"6A00", "No information given (Bytes P1 and/or P2 are incorrect)"},
    {"6A80", "The parameters in the data field are incorrect."},
    {"6A81", "Function not supported"},
    {"6A82", "File not found"},
    {"6A83", "Record not found"},
    {"6A84", "There is insufficient memory space in record or file"},
    {"6A85", "Lc inconsistent with TLV structure"},
    {"6A86", "Incorrect P1 or P2 parameter."},
    {"6A87", "Lc inconsistent with P1-P2"},
    {"6A88", "Referenced data not found"},
    {"6A89", "File already exists"},
    {"6A8A", "DF name already exists."},
    {"6AF0", "Wrong parameter value"},
    {"6B00", "Wrong parameter(s) P1-P2"},
    {"6C00", "Incorrect P3 length."},
    {"6D00", "Instruction code not supported or invalid"},
    {"6E00", "Class not supported"},
    {"6F00", "Command aborted - more exact diagnosis not possible (e.g., operating system error)."},
    {"6FFF", "Card dead (overuse, ...)"},
    {"9000", "Command successfully executed (OK)."},
    {"9004", "PIN not succesfully verified, 3 or more PIN tries left"},
    {"9008", "Key/file not found"},
    {"9080", "Unblock Try Counter has reached zero"},
    {"9100", "OK"},
    {"9101", "States.activity, States.lock Status or States.lockable has wrong value"},
    {"9102", "Transaction number reached its limit"},
    {"910C", "No changes"},
    {"910E", "Insufficient NV-Memory to complete command"},
    {"911C", "Command code not supported"},
    {"911E", "CRC or MAC does not match data"},
    {"9140", "Invalid key number specified"},
    {"917E", "Length of command string invalid"},
    {"919D", "Not allow the requested command"},
    {"919E", "Value of the parameter invalid"},
    {"91A0", "Requested AID not present on PICC"},
    {"91A1", "Unrecoverable error within application"},
    {"91AE", "Authentication status does not allow the requested command"},
    {"91AF", "Additional data frame is expected to be sent"},
    {"91BE", "Out of boundary"},
    {"91C1", "Unrecoverable error within PICC"},
    {"91CA", "Previous Command was not fully completed"},
    {"91CD", "PICC was disabled by an unrecoverable error"},
    {"91CE", "Number of Applications limited to 28"},
    {"91DE", "File or application already exists"},
    {"91EE", "Could not complete NV-write operation due to loss of power"},
    {"91F0", "Specified file number does not exist"},
    {"91F1", "Unrecoverable error within file"},
    {"9210", "Insufficient memory. No more storage available."},
    {"9240", "Writing to EEPROM not successful."},
    {"9301", "Integrity error"},
    {"9302", "Candidate S2 invalid"},
    {"9303", "Application is permanently locked"},
    {"9400", "No EF selected."},
    {"9401", "Candidate currency code does not match purse currency"},
    {"9402", "Candidate amount too high"},
    {"9402", "Address range exceeded."},
    {"9403", "Candidate amount too low"},
    {"9404", "FID not found, record not found or comparison pattern not found."},
    {"9405", "Problems in the data field"},
    {"9406", "Required MAC unavailable"},
    {"9407", "Bad currency : purse engine has no slot with R3bc currency"},
    {"9408", "R3bc currency not supported in purse engine"},
    {"9408", "Selected file type does not match command."},
    {"9580", "Bad sequence"},
    {"9681", "Slave not found"},
    {"9700", "PIN blocked and Unblock Try Counter is 1 or 2"},
    {"9702", "Main keys are blocked"},
    {"9704", "PIN not succesfully verified, 3 or more PIN tries left"},
    {"9784", "Base key"},
    {"9785", "Limit exceeded - C-MAC key"},
    {"9786", "SM error - Limit exceeded - R-MAC key"},
    {"9787", "Limit exceeded - sequence counter"},
    {"9788", "Limit exceeded - R-MAC length"},
    {"9789", "Service not available"},
    {"9802", "No PIN defined."},
    {"9804", "Access conditions not satisfied, authentication failed."},
    {"9835", "ASK RANDOM or GIVE RANDOM not executed."},
    {"9840", "PIN verification not successful."},
    {"9850", "INCREASE or DECREASE could not be executed because a limit has been reached."},
    {"9862", "Authentication Error, application specific (incorrect MAC)"},
    {"9900", "1 PIN try left"},
    {"9904", "PIN not succesfully verified, 1 PIN try left"},
    {"9985", "Wrong status - Cardholder lock"},
    {"9986", "Missing privilege"},
    {"9987", "PIN is not installed"},
    {"9988", "Wrong status - R-MAC state"},
    {"9A00", "2 PIN try left"},
    {"9A04", "PIN not succesfully verified, 2 PIN try left"},
    {"9A71", "Wrong parameter value - Double agent AID"},
    {"9A72", "Wrong parameter value - Double agent Type"},
    {"9D05", "Incorrect certificate type"},
    {"9D07", "Incorrect session data size"},
    {"9D08", "Incorrect DIR file record size"},
    {"9D09", "Incorrect FCI record size"},
    {"9D0A", "Incorrect code size"},
    {"9D10", "Insufficient memory to load application"},
    {"9D11", "Invalid AID"},
    {"9D12", "Duplicate AID"},
    {"9D13", "Application previously loaded"},
    {"9D14", "Application history list full"},
    {"9D15", "Application not open"},
    {"9D17", "Invalid offset"},
    {"9D18", "Application already loaded"},
    {"9D19", "Invalid certificate"},
    {"9D1A", "Invalid signature"},
    {"9D1B", "Invalid KTU"},
    {"9D1D", "MSM controls not set"},
    {"9D1E", "Application signature does not exist"},
    {"9D1F", "KTU does not exist"},
    {"9D20", "Application not loaded"},
    {"9D21", "Invalid Open command data length"},
    {"9D30", "Check data parameter is incorrect (invalid start address)"},
    {"9D31", "Check data parameter is incorrect (invalid length)"},
    {"9D32", "Check data parameter is incorrect (illegal memory check area)"},
    {"9D40", "Invalid MSM Controls ciphertext"},
    {"9D41", "MSM controls already set"},
    {"9D42", "Set MSM Controls data length less than 2 bytes"},
    {"9D43", "Invalid MSM Controls data length"},
    {"9D44", "Excess MSM Controls ciphertext"},
    {"9D45", "Verification of MSM Controls data failed"},
    {"9D50", "Invalid MCD Issuer production ID"},
    {"9D51", "Invalid MCD Issuer ID"},
    {"9D52", "Invalid set MSM controls data date"},
    {"9D53", "Invalid MCD number"},
    {"9D54", "Reserved field error"},
    {"9D55", "Reserved field error"},
    {"9D56", "Reserved field error"},
    {"9D57", "Reserved field error"},
    {"9D60", "MAC verification failed"},
    {"9D61", "Maximum number of unblocks reached"},
    {"9D62", "Card was not blocked"},
    {"9D63", "Crypto functions not available"},
    {"9D64", "No application loaded"},
    {"9E00", "PIN not installed"},
    {"9E04", "PIN not succesfully verified, PIN not installed"},
    {"9F00", "PIN blocked and Unblock Try Counter is 3"},
    {"9F04", "PIN not succesfully verified, PIN blocked and Unblock Try Counter is 3"}
};

static const iso14a_polling_frame_t WUPA_FRAME = { //ISO14443 Type A Polling frame
    .frame = { 0x52 },
    .frame_length = 1,
    .last_byte_bits = 7,
    .extra_delay = 0,
};

static const iso14a_polling_frame_t ECP_VAS_ONLY_FRAME = { //ISO14443 Type A Polling frame for VAS only
    .frame = {0x6a, 0x01, 0x00, 0x00, 0x02, 0xe4, 0xd2},
    .frame_length = 7,
    .last_byte_bits = 8,
    .extra_delay = 0,
};

uint8_t aid[] = { 0x4f, 0x53, 0x45, 0x2e, 0x56, 0x41, 0x53, 0x2e, 0x30, 0x31 }; // OSE.VAS.01 in HEX
uint8_t getVasUrlOnlyP2 = 0x00; // VAS URL only mode
uint8_t getVasFullReqP2 = 0x01; // VAS full mode

static int ParseSelectVASResponse(const uint8_t *response, size_t resLen, bool verbose) { // Interpret the response from sending the aid
    struct tlvdb *tlvRoot = tlvdb_parse_multi(response, resLen); 

    const struct tlvdb *versionTlv = tlvdb_find_full(tlvRoot, 0x9F21); //find version TLV, 0x9F21 = 40737
    if (versionTlv == NULL) {
        tlvdb_free(tlvRoot);
        return PM3_ECARDEXCHANGE; //if version is empty, return error
    }
    const struct tlv *version = tlvdb_get_tlv(versionTlv);
    if (version->len != 2) {
        tlvdb_free(tlvRoot);
        return PM3_ECARDEXCHANGE; //if version in not of length 2, return error
    }
    if (verbose) {
        PrintAndLogEx(INFO, "Mobile VAS application version: %d.%d", version->value[0], version->value[1]);
    }
    if (version->value[0] != 0x01 || version->value[1] != 0x00) {
        tlvdb_free(tlvRoot);
        return PM3_ECARDEXCHANGE; //return error if version isn't 1.0
    }

    const struct tlvdb *capabilitiesTlv = tlvdb_find_full(tlvRoot, 0x9F23); //find capabilities mask TLV, 0x9F23 = 40739
    if (capabilitiesTlv == NULL) {
        tlvdb_free(tlvRoot);
        return PM3_ECARDEXCHANGE; //If no capabilities mask, return error
    }
    const struct tlv *capabilities = tlvdb_get_tlv(capabilitiesTlv); //find capabilities mask
    if (capabilities->len != 4
            || capabilities->value[0] != 0x00
            || capabilities->value[1] != 0x00
            || capabilities->value[2] != 0x00
            || (capabilities->value[3] & 8) == 0) { //If capabilities length is not 4, or values [0..2] are not zero, or value [3] is not set, free memory and return error
        tlvdb_free(tlvRoot);
        return PM3_ECARDEXCHANGE;
    }

    tlvdb_free(tlvRoot); //if no error returned, we have the response, version, and capabilities mask!
    return PM3_SUCCESS;
}

static int CreateGetVASDataCommand(const uint8_t *pidHash, const char *url, size_t urlLen, uint8_t *out, int *outLen) {
    if (pidHash == NULL && url == NULL) {
        PrintAndLogEx(FAILED, "Must provide a Pass Type ID or a URL");
        return PM3_EINVARG;
    }

    if (url != NULL && urlLen > 256) {
        PrintAndLogEx(FAILED, "URL must be less than 256 characters");
        return PM3_EINVARG;
    }

    uint8_t p2 = pidHash == NULL ? getVasUrlOnlyP2 : getVasFullReqP2;

    size_t reqTlvLen = 19 + (pidHash != NULL ? 35 : 0) + (url != NULL ? 3 + urlLen : 0);
    uint8_t *reqTlv = calloc(reqTlvLen, sizeof(uint8_t));

    uint8_t version[] = {0x9F, 0x22, 0x02, 0x01, 0x00};
    memcpy(reqTlv, version, sizeof(version));

    uint8_t unknown[] = {0x9F, 0x28, 0x04, 0x00, 0x00, 0x00, 0x00};
    memcpy(reqTlv + sizeof(version), unknown, sizeof(unknown));

    uint8_t terminalCapabilities[] = {0x9F, 0x26, 0x04, 0x00, 0x00, 0x00, 0x02};
    memcpy(reqTlv + sizeof(version) + sizeof(unknown), terminalCapabilities, sizeof(terminalCapabilities));

    if (pidHash != NULL) {
        size_t offset = sizeof(version) + sizeof(unknown) + sizeof(terminalCapabilities);
        reqTlv[offset] = 0x9F;
        reqTlv[offset + 1] = 0x25;
        reqTlv[offset + 2] = 32;
        memcpy(reqTlv + offset + 3, pidHash, 32);
    }

    if (url != NULL) {
        size_t offset = sizeof(version) + sizeof(unknown) + sizeof(terminalCapabilities) + (pidHash != NULL ? 35 : 0);
        reqTlv[offset] = 0x9F;
        reqTlv[offset + 1] = 0x29;
        reqTlv[offset + 2] = urlLen;
        memcpy(reqTlv + offset + 3, url, urlLen);
    }

    out[0] = 0x80;
    out[1] = 0xCA;
    out[2] = 0x01;
    out[3] = p2;
    out[4] = reqTlvLen;
    memcpy(out + 5, reqTlv, reqTlvLen);
    out[5 + reqTlvLen] = 0x00;

    *outLen = 6 + reqTlvLen;

    free(reqTlv);
    return PM3_SUCCESS;
}

static int ParseGetVASDataResponse(const uint8_t *res, size_t resLen, uint8_t *cryptogram, size_t *cryptogramLen) {
    struct tlvdb *tlvRoot = tlvdb_parse_multi(res, resLen);

    const struct tlvdb *cryptogramTlvdb = tlvdb_find_full(tlvRoot, 0x9F27);
    if (cryptogramTlvdb == NULL) {
        tlvdb_free(tlvRoot);
        return PM3_ECARDEXCHANGE;
    }
    const struct tlv *cryptogramTlv = tlvdb_get_tlv(cryptogramTlvdb);

    parseTaggedList(res);

    memcpy(cryptogram, cryptogramTlv->value, cryptogramTlv->len);
    *cryptogramLen = cryptogramTlv->len;

    tlvdb_free(tlvRoot);
    return PM3_SUCCESS;
}

static int LoadReaderPrivateKey(const uint8_t *buf, size_t bufLen, mbedtls_ecp_keypair *privKey) {
    struct tlvdb *derRoot = tlvdb_parse_multi(buf, bufLen);

    const struct tlvdb *privkeyTlvdb = tlvdb_find_full(derRoot, 0x04);
    if (privkeyTlvdb == NULL) {
        tlvdb_free(derRoot);
        return PM3_EINVARG;
    }
    const struct tlv *privkeyTlv = tlvdb_get_tlv(privkeyTlvdb);

    if (mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, privKey, privkeyTlv->value, privkeyTlv->len)) {
        tlvdb_free(derRoot);
        PrintAndLogEx(FAILED, "Unable to parse private key file. Should be DER encoded ASN1");
        return PM3_EINVARG;
    }

    const struct tlvdb *pubkeyCoordsTlvdb = tlvdb_find_full(derRoot, 0x03);
    if (pubkeyCoordsTlvdb == NULL) {
        tlvdb_free(derRoot);
        PrintAndLogEx(FAILED, "Private key file should include public key component");
        return PM3_EINVARG;
    }
    const struct tlv *pubkeyCoordsTlv = tlvdb_get_tlv(pubkeyCoordsTlvdb);
    if (pubkeyCoordsTlv->len != 66 || pubkeyCoordsTlv->value[0] != 0x00 || pubkeyCoordsTlv->value[1] != 0x04) {
        tlvdb_free(derRoot);
        PrintAndLogEx(FAILED, "Invalid public key data");
        return PM3_EINVARG;
    }

    if (mbedtls_ecp_point_read_binary(&privKey->grp, &privKey->Q, pubkeyCoordsTlv->value + 1, 65)) {
        PrintAndLogEx(FAILED, "Failed to read in public key coordinates");
        tlvdb_free(derRoot);
        return PM3_EINVARG;
    }

    if (mbedtls_ecp_check_pubkey(&privKey->grp, &privKey->Q)) {
        PrintAndLogEx(FAILED, "VAS protocol requires an elliptic key on the P-256 curve");
        tlvdb_free(derRoot);
        return PM3_EINVARG;
    }

    tlvdb_free(derRoot);
    return PM3_SUCCESS;
}

static int GetPrivateKeyHint(mbedtls_ecp_keypair *privKey, uint8_t *keyHint) {
    uint8_t xcoord[32] = {0};
    if (mbedtls_mpi_write_binary(&privKey->Q.X, xcoord, sizeof(xcoord))) {
        return PM3_EINVARG;
    }

    uint8_t hash[32] = {0};
    sha256hash(xcoord, 32, hash);

    memcpy(keyHint, hash, 4);
    return PM3_SUCCESS;
}

static int LoadMobileEphemeralKey(const uint8_t *xcoordBuf, mbedtls_ecp_keypair *pubKey) {
    uint8_t compressedEcKey[33] = {0};
    compressedEcKey[0] = 0x02;
    memcpy(compressedEcKey + 1, xcoordBuf, 32);

    uint8_t decompressedEcKey[65] = {0};
    size_t decompressedEcKeyLen = 0;
    if (mbedtls_ecp_decompress(&pubKey->grp, compressedEcKey, sizeof(compressedEcKey), decompressedEcKey, &decompressedEcKeyLen, sizeof(decompressedEcKey))) {
        return PM3_EINVARG;
    }

    if (mbedtls_ecp_point_read_binary(&pubKey->grp, &pubKey->Q, decompressedEcKey, decompressedEcKeyLen)) {
        return PM3_EINVARG;
    }

    return PM3_SUCCESS;
}

static int internalVasDecrypt(uint8_t *cipherText, size_t cipherTextLen, uint8_t *sharedSecret,
                              uint8_t *ansiSharedInfo, size_t ansiSharedInfoLen,
                              const uint8_t *gcmAad, size_t gcmAadLen, uint8_t *out, size_t *outLen) {
    uint8_t key[32] = {0};
    if (ansi_x963_sha256(sharedSecret, 32, ansiSharedInfo, ansiSharedInfoLen, sizeof(key), key)) {
        PrintAndLogEx(FAILED, "ANSI X9.63 key derivation failed");
        return PM3_EINVARG;
    }

    uint8_t iv[16] = {0};

    mbedtls_gcm_context gcmCtx;
    mbedtls_gcm_init(&gcmCtx);
    if (mbedtls_gcm_setkey(&gcmCtx, MBEDTLS_CIPHER_ID_AES, key, sizeof(key) * 8)) {
        PrintAndLogEx(FAILED, "Unable to use key in GCM context");
        return PM3_EINVARG;
    }

    if (mbedtls_gcm_auth_decrypt(&gcmCtx, cipherTextLen - 16, iv, sizeof(iv), gcmAad, gcmAadLen, cipherText + cipherTextLen - 16, 16, cipherText, out)) {
        PrintAndLogEx(FAILED, "Failed to perform GCM decryption");
        return PM3_EINVARG;
    }

    mbedtls_gcm_free(&gcmCtx);

    *outLen = cipherTextLen - 16;

    return PM3_SUCCESS;
}

static int DecryptVASCryptogram(uint8_t *pidHash, uint8_t *cryptogram, size_t cryptogramLen, mbedtls_ecp_keypair *privKey, uint8_t *out, size_t *outLen, uint32_t *timestamp) {
    uint8_t keyHint[4] = {0};
    if (GetPrivateKeyHint(privKey, keyHint) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Unable to generate key hint");
        return PM3_EINVARG;
    }

    if (memcmp(keyHint, cryptogram, 4) != 0) {
        PrintAndLogEx(FAILED, "Private key does not match cryptogram");
        return PM3_EINVARG;
    }

    mbedtls_ecp_keypair mobilePubKey;
    mbedtls_ecp_keypair_init(&mobilePubKey);
    mobilePubKey.grp = privKey->grp;

    if (LoadMobileEphemeralKey(cryptogram + 4, &mobilePubKey) != PM3_SUCCESS) {
        mbedtls_ecp_keypair_free(&mobilePubKey);
        PrintAndLogEx(FAILED, "Unable to parse mobile ephemeral key from cryptogram");
        return PM3_EINVARG;
    }

    mbedtls_mpi sharedSecret;
    mbedtls_mpi_init(&sharedSecret);

    if (mbedtls_ecdh_compute_shared(&privKey->grp, &sharedSecret, &mobilePubKey.Q, &privKey->d, NULL, NULL)) {
        mbedtls_mpi_free(&sharedSecret);
        mbedtls_ecp_keypair_free(&mobilePubKey);
        PrintAndLogEx(FAILED, "Failed to generate ECDH shared secret");
        return PM3_EINVARG;
    }
    mbedtls_ecp_keypair_free(&mobilePubKey);

    uint8_t sharedSecretBytes[32] = {0};
    if (mbedtls_mpi_write_binary(&sharedSecret, sharedSecretBytes, sizeof(sharedSecretBytes))) {
        mbedtls_mpi_free(&sharedSecret);
        PrintAndLogEx(FAILED, "Failed to generate ECDH shared secret");
        return PM3_EINVARG;
    }
    mbedtls_mpi_free(&sharedSecret);

    uint8_t string1[27] = "ApplePay encrypted VAS data";
    uint8_t string2[13] = "id-aes256-GCM";

    uint8_t method1SharedInfo[73] = {0};
    method1SharedInfo[0] = 13;
    memcpy(method1SharedInfo + 1, string2, sizeof(string2));
    memcpy(method1SharedInfo + 1 + sizeof(string2), string1, sizeof(string1));
    memcpy(method1SharedInfo + 1 + sizeof(string2) + sizeof(string1), pidHash, 32);

    uint8_t decryptedData[68] = {0};
    size_t decryptedDataLen = 0;
    if (internalVasDecrypt(cryptogram + 4 + 32, cryptogramLen - 4 - 32, sharedSecretBytes, method1SharedInfo, sizeof(method1SharedInfo), NULL, 0, decryptedData, &decryptedDataLen)) {
        if (internalVasDecrypt(cryptogram + 4 + 32, cryptogramLen - 4 - 32, sharedSecretBytes, string1, sizeof(string1), pidHash, 32, decryptedData, &decryptedDataLen)) {
            return PM3_EINVARG;
        }
    }

    memcpy(out, decryptedData + 4, decryptedDataLen - 4);
    *outLen = decryptedDataLen - 4;

    *timestamp = 0;
    for (int i = 0; i < 4; ++i) {
        *timestamp = (*timestamp << 8) | decryptedData[i];
    }

    return PM3_SUCCESS;
}

static void PrintCoordinate(mbedtls_mpi *mpi) {
    // Print the number in little-endian order (least significant limb first)
    for (int i = mpi->n - 1; i >= 0; i--) {
        printf("%016llx", (unsigned long long)mpi->p[i]); // Assuming each limb is a 64-bit unsigned integer
    }
}

static int VASReader(uint8_t *pidHash, const char *url, size_t urlLen, uint8_t *cryptogram, size_t *cryptogramLen, bool verbose) {
    clearCommandBuffer();

    iso14a_polling_parameters_t polling_parameters = {
        .frames = { WUPA_FRAME, ECP_VAS_ONLY_FRAME },
        .frame_count = 2,
        .extra_timeout = 250
    };

    if (SelectCard14443A_4_WithParameters(false, false, NULL, &polling_parameters) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "No ISO14443-A Card in field");
        return PM3_ECARDEXCHANGE;
    }

    uint16_t status = 0;
    size_t resLen = 0;
    uint8_t selectResponse[APDU_RES_LEN] = {0};
    Iso7816Select(CC_CONTACTLESS, false, true, aid, sizeof(aid), selectResponse, APDU_RES_LEN, &resLen, &status);

    if (status != 0x9000) {
        PrintAndLogEx(FAILED, "Card doesn't support VAS");
        return PM3_ECARDEXCHANGE;
    }

    if (ParseSelectVASResponse(selectResponse, resLen, verbose) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Card doesn't support VAS");
        return PM3_ECARDEXCHANGE;
    }

    uint8_t getVasApdu[PM3_CMD_DATA_SIZE];
    int getVasApduLen = 0;

    int s = CreateGetVASDataCommand(pidHash, url, urlLen, getVasApdu, &getVasApduLen);
    if (s != PM3_SUCCESS) {
        return s;
    }

    uint8_t apduRes[APDU_RES_LEN] = {0};
    int apduResLen = 0;
    
    s = ExchangeAPDU14a(getVasApdu, getVasApduLen, false, false, apduRes, APDU_RES_LEN, &apduResLen);
    if (s != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Failed to send APDU");
        return s;
    }

    if (apduResLen == 2 && apduRes[0] == 0x62 && apduRes[1] == 0x87) {
        PrintAndLogEx(WARNING, "Device returned error on GET VAS DATA. Either doesn't have pass with matching id, or requires user authentication.");
        return PM3_ECARDEXCHANGE;
    }

    if (apduResLen == 0 || apduRes[0] != 0x70) {
        PrintAndLogEx(FAILED, "Invalid response from peer");
    }

    return ParseGetVASDataResponse(apduRes, apduResLen, cryptogram, cryptogramLen);
}

static int CmdVASReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf vas reader",
                  "Read and decrypt Value Added Services (VAS) message",
                  "hf vas reader --url https://example.com    -> URL Only mode\n"
                  "hf vas reader --pid pass.com.passkit.pksamples.nfcdemo -f vas_privkey.der -@\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "pid", "<str>", "PID, pass type id"),
        arg_str0("f", "file", "<fn>", "path to terminal private key file"),
        arg_str0(NULL, "url", "<str>", "a URL to provide to the mobile device"),
        arg_lit0("@", NULL, "continuous mode"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int pidlen = 0;
    char pid[512] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)pid, 512, &pidlen);

    int keyfnlen = 0;
    char keyfn[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)keyfn, FILE_PATH_SIZE, &keyfnlen);

    if (keyfnlen == 0 && pidlen > 0) {
        PrintAndLogEx(FAILED, "Must provide path to terminal private key if a pass type id is provided");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int urllen = 0;
    char url[512] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 3), (uint8_t *)url, 512, &urllen);

    bool continuous = arg_get_lit(ctx, 4);
    bool verbose = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    // santity checks
    uint8_t *key_data = NULL;
    size_t key_datalen = 0;
    if (loadFile_safe(keyfn, "", (void **)&key_data, &key_datalen) != PM3_SUCCESS) {
        return PM3_EFILE;
    }

    mbedtls_ecp_keypair privKey;
    mbedtls_ecp_keypair_init(&privKey);

    if (LoadReaderPrivateKey(key_data, key_datalen, &privKey) != PM3_SUCCESS) {
        free(key_data);
        mbedtls_ecp_keypair_free(&privKey);
        return PM3_ESOFT;
    }
    free(key_data);

    PrintAndLogEx(INFO, "Requesting pass type id... " _GREEN_("%s"), sprint_ascii((uint8_t *) pid, pidlen));

    if (continuous) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    uint8_t pidhash[32] = {0};
    sha256hash((uint8_t *) pid, pidlen, pidhash);

    size_t clen = 0;
    size_t mlen = 0;
    uint8_t cryptogram[120] = {0};
    uint8_t msg[64] = {0};
    uint32_t timestamp = 0;
    int res = PM3_SUCCESS;

    do {
        if (continuous && kbd_enter_pressed()) {
            break;
        }

        res = VASReader((pidlen > 0) ? pidhash : NULL, url, urllen, cryptogram, &clen, verbose);
        if (res == PM3_SUCCESS) {

            res = DecryptVASCryptogram(pidhash, cryptogram, clen, &privKey, msg, &mlen, &timestamp);
            if (res == PM3_SUCCESS) {
                PrintAndLogEx(SUCCESS, "Cryptogram... ");
                for (int i = 0; i < clen; i++) {
                     printf("%02X", cryptogram[i]);
                };
                printf("\n");
                PrintAndLogEx(SUCCESS, "Pass ID Hash... ");
                for (int i = 0; i < sizeof(pidhash); i++) {
                     printf("%02X", pidhash[i]);
                };
                printf("\n");
                PrintAndLogEx(SUCCESS, "===== ELLIPTIC CURVE DATA... =====");
                PrintAndLogEx (INFO, "Curve type... ");
                switch(privKey.grp.id) {
                    case 0:
                        printf("not defined \n");
                        break;
                    case 1:
                        printf("Domain parameters for the 192-bit curve defined by FIPS 186-4 and SEC1.\n");
                        break;
                    case 2:
                        printf("Domain parameters for the 224-bit curve defined by FIPS 186-4 and SEC1.\n");
                        break;
                    case 3:
                        printf("Domain parameters for the 256-bit curve defined by FIPS 186-4 and SEC1.\n");
                        break;
                    case 4:
                        printf("Domain parameters for the 384-bit curve defined by FIPS 186-4 and SEC1.\n");
                        break;
                    case 5:
                        printf("Domain parameters for the 521-bit curve defined by FIPS 186-4 and SEC1.\n");
                        break;
                    case 6:
                        printf("Domain parameters for 256-bit Brainpool curve.\n");
                        break;
                    case 7:
                        printf("Domain parameters for 384-bit Brainpool curve.\n");
                        break;
                    case 8:
                        printf("Domain parameters for 512-bit Brainpool curve.\n");
                        break;
                    case 9:
                        printf("Domain parameters for Curve25519.");
                        break;
                    case 10:
                        printf("Domain parameters for 192-bit \"Koblitz\" curve.");
                        break;
                    case 11:
                        printf("Domain parameters for 224-bit \"Koblitz\" curve.\n");
                        break;
                    case 12:
                        printf("Domain parameters for 256-bit \"Koblitz\" curve.\n");
                        break;
                    case 13:
                        printf("Domain parameters for Curve448.\n");
                        break;
                    case 14:
                        printf("Domain parameters for the 128-bit curve used for NXP originality check.\n");
                        break;
                    default:
                        printf("Unknown curve ID.\n");
                }
                PrintAndLogEx(INFO, "Public value in hexadecimal... ");
                printf("X: ");
                PrintCoordinate(&privKey.Q.X);
                    printf(", ");
                printf("Y: ");
                PrintCoordinate(&privKey.Q.Y);
                    printf(", ");
                printf("Z: ");
                PrintCoordinate(&privKey.Q.Z);
                printf("\n");
                
                PrintAndLogEx(SUCCESS, "Timestamp... " _YELLOW_("%d") " (secs since Jan 1, 2001)", timestamp);
                PrintAndLogEx(SUCCESS, "Message..... " _YELLOW_("%s"), sprint_ascii(msg, mlen));
                // extra sleep after successfull read
                if (continuous) {
                    msleep(3000);
                }
            }
        }
        msleep(300);
    } while (continuous);

    mbedtls_ecp_keypair_free(&privKey);
    return res;
}

static int CmdVASDecrypt(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf vas decrypt",
                  "Decrypt a previously captured cryptogram",
                  "hf vas decrypt --pid pass.com.passkit.pksamples.nfcdemo -f vas_privkey.der -d c0b77375eae416b79449347f9fe838c05cdb57dc7470b97b93b806cb348771d9bfbe29d58538c7c7d7c3d015fa205b68bfccd726058a62f7f44085ac98dbf877120fd9059f1507b956e0a6d56d0a\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "pid", "<str>", "PID, pass type id"),
        arg_str0("f", "file", "<fn>", "path to terminal private key file"),
        arg_str0("d", "data", "<hex>", "cryptogram to decrypt"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int pidlen = 0;
    char pid[512] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)pid, 512, &pidlen);

    int keyfnlen = 0;
    char keyfn[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)keyfn, FILE_PATH_SIZE, &keyfnlen);

    if (keyfnlen == 0 && pidlen > 0) {
        PrintAndLogEx(FAILED, "Must provide path to terminal private key if a pass type id is provided");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int clen = 0;
    uint8_t cryptogram[120] = {0};
    CLIGetHexWithReturn(ctx, 3, cryptogram, &clen);
    CLIParserFree(ctx);

    // santity checks
    uint8_t *key_data = NULL;
    size_t key_datalen = 0;
    if (loadFile_safe(keyfn, "", (void **)&key_data, &key_datalen) != PM3_SUCCESS) {
        return PM3_EFILE;
    }

    mbedtls_ecp_keypair privKey;
    mbedtls_ecp_keypair_init(&privKey);

    if (LoadReaderPrivateKey(key_data, key_datalen, &privKey) != PM3_SUCCESS) {
        free(key_data);
        mbedtls_ecp_keypair_free(&privKey);
        return PM3_EFILE;
    }
    free(key_data);

    uint8_t pidhash[32] = {0};
    sha256hash((uint8_t *) pid, pidlen, pidhash);

    size_t mlen = 0;
    uint8_t msg[64] = {0};
    uint32_t timestamp = 0;

    int res = DecryptVASCryptogram(pidhash, cryptogram, clen, &privKey, msg, &mlen, &timestamp);
    if (res == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Timestamp... " _YELLOW_("%d") " (secs since Jan 1, 2001)", timestamp);
        PrintAndLogEx(SUCCESS, "Message..... " _YELLOW_("%s"), sprint_ascii(msg, mlen));
    }

    mbedtls_ecp_keypair_free(&privKey);
    return res;
}

static int CmdHelp(const char *Cmd);

static command_t CommandTable[] = {
    {"--------",  CmdHelp,        AlwaysAvailable,  "----------- " _CYAN_("Value Added Service") " -----------"},
    {"help",      CmdHelp,        AlwaysAvailable,  "This help"},
    {"--------",  CmdHelp,        AlwaysAvailable,  "----------------- " _CYAN_("General") " -----------------"},
    {"reader",    CmdVASReader,   IfPm3Iso14443a,   "Read and decrypt VAS message"},
    {"decrypt",   CmdVASDecrypt,  AlwaysAvailable,  "Decrypt a previously captured VAS cryptogram"},
    {NULL, NULL, NULL, NULL}
};

int CmdHFVAS(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}
