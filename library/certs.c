/*
 *  X.509 test certificates
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 *
 *  This file is provided under the Apache License 2.0, or the
 *  GNU General Public License v2.0 or later.
 *
 *  **********
 *  Apache License 2.0:
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  **********
 *
 *  **********
 *  GNU General Public License v2.0 or later:
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  **********
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/certs.h"

#if defined(MBEDTLS_CERTS_C)

/*
 * Test CA Certificates
 *
 * We define test CA certificates for each choice of the following parameters:
 * - PEM or DER encoding
 * - SHA-1 or SHA-256 hash
 * - RSA or EC key
 *
 * Things to add:
 * - multiple EC curve types
 *
 */

/* This is taken from tests/data_files/test-ca2.crt */
/* BEGIN FILE string macro TEST_CA_CRT_EC_PEM tests/data_files/test-ca2.crt */
#define TEST_CA_CRT_EC_PEM                                                 \
  "-----BEGIN CERTIFICATE-----\r\n"	\
  "MIICOTCCAZmgAwIBAgIBATAMBggqhkjOPQQDAgUAMDYxGTAXBgNVBAMMEFJvb3Qg\r\n"	\
  "Q2VydGlmaWNhdGUxDDAKBgNVBAoMA1VvUzELMAkGA1UEBhMCVUswHhcNMjIwMTAx\r\n"	\
  "MDAwMDAwWhcNMjcwMTAxMDAwMDAwWjA2MRkwFwYDVQQDDBBSb290IENlcnRpZmlj\r\n"	\
  "YXRlMQwwCgYDVQQKDANVb1MxCzAJBgNVBAYTAlVLMIGbMBAGByqGSM49AgEGBSuB\r\n"	\
  "BAAjA4GGAAQAUGUOZfOnbF7C13vbZ5GBTo+0L7SARkvYoAxVowH3ukevnRcR/0oE\r\n"	\
  "CgElNAf7ySlOKYnztnLpsU2580X133RVykcBrzBnjkTvcXNRfTVZtdZcvyGpSbNC\r\n"	\
  "gP+495/gqNY5Hx4j5HnNJtyUoHliFzTnyDI+YjlEWrTHxVmFqWcSbeAPwTOjUzBR\r\n"	\
  "MA8GA1UdEwQIMAYBAf8CAQAwHQYDVR0OBBYEFMzm7Zvhd0Uk2cl/IYGuC0ANtQvC\r\n"	\
  "MB8GA1UdIwQYMBaAFMzm7Zvhd0Uk2cl/IYGuC0ANtQvCMAwGCCqGSM49BAMCBQAD\r\n"	\
  "gYsAMIGHAkIA2Zc10EnLY+dBKiaE7+cQMdxIN2RaRWxVyDqr0AjH5dndiDppzqiv\r\n"	\
  "EKT7oVm4pHYPrsrM3CHbrOYWkanugutCQuACQSntrj6Pcjow0quXPMcZt+OFrodl\r\n"	\
  "DNpjDH77Pr0NX2W1pFNY0TUT2tmTyaw+eta3PYnFnSDr6irGphITNMN0Qwq5\r\n"	\
  "-----END CERTIFICATE-----\r\n"	  
/* END FILE */

/* This is generated from tests/data_files/test-ca2.crt.der using `xxd -i`. */
/* BEGIN FILE binary macro TEST_CA_CRT_EC_DER tests/data_files/test-ca2.crt.der */
#define TEST_CA_CRT_EC_DER {                                                 \
  0x30, 0x82, 0x02, 0x04, 0x30, 0x82, 0x01, 0x88, 0xa0, 0x03, 0x02, 0x01,    \
  0x02, 0x02, 0x09, 0x00, 0xc1, 0x43, 0xe2, 0x7e, 0x62, 0x43, 0xcc, 0xe8,    \
  0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,    \
  0x05, 0x00, 0x30, 0x3e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,    \
  0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55,    \
  0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c,    \
  0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x13, 0x50,    \
  0x6f, 0x6c, 0x61, 0x72, 0x73, 0x73, 0x6c, 0x20, 0x54, 0x65, 0x73, 0x74,    \
  0x20, 0x45, 0x43, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x39,    \
  0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34, 0x34, 0x30, 0x30, 0x5a, 0x17,    \
  0x0d, 0x32, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34, 0x34, 0x30,    \
  0x30, 0x5a, 0x30, 0x3e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,    \
  0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55,    \
  0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c,    \
  0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x13, 0x50,    \
  0x6f, 0x6c, 0x61, 0x72, 0x73, 0x73, 0x6c, 0x20, 0x54, 0x65, 0x73, 0x74,    \
  0x20, 0x45, 0x43, 0x20, 0x43, 0x41, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07,    \
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04,    \
  0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0xc3, 0xda, 0x2b, 0x34, 0x41, 0x37,    \
  0x58, 0x2f, 0x87, 0x56, 0xfe, 0xfc, 0x89, 0xba, 0x29, 0x43, 0x4b, 0x4e,    \
  0xe0, 0x6e, 0xc3, 0x0e, 0x57, 0x53, 0x33, 0x39, 0x58, 0xd4, 0x52, 0xb4,    \
  0x91, 0x95, 0x39, 0x0b, 0x23, 0xdf, 0x5f, 0x17, 0x24, 0x62, 0x48, 0xfc,    \
  0x1a, 0x95, 0x29, 0xce, 0x2c, 0x2d, 0x87, 0xc2, 0x88, 0x52, 0x80, 0xaf,    \
  0xd6, 0x6a, 0xab, 0x21, 0xdd, 0xb8, 0xd3, 0x1c, 0x6e, 0x58, 0xb8, 0xca,    \
  0xe8, 0xb2, 0x69, 0x8e, 0xf3, 0x41, 0xad, 0x29, 0xc3, 0xb4, 0x5f, 0x75,    \
  0xa7, 0x47, 0x6f, 0xd5, 0x19, 0x29, 0x55, 0x69, 0x9a, 0x53, 0x3b, 0x20,    \
  0xb4, 0x66, 0x16, 0x60, 0x33, 0x1e, 0xa3, 0x50, 0x30, 0x4e, 0x30, 0x0c,    \
  0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff,    \
  0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x9d,    \
  0x6d, 0x20, 0x24, 0x49, 0x01, 0x3f, 0x2b, 0xcb, 0x78, 0xb5, 0x19, 0xbc,    \
  0x7e, 0x24, 0xc9, 0xdb, 0xfb, 0x36, 0x7c, 0x30, 0x1f, 0x06, 0x03, 0x55,    \
  0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x9d, 0x6d, 0x20, 0x24,    \
  0x49, 0x01, 0x3f, 0x2b, 0xcb, 0x78, 0xb5, 0x19, 0xbc, 0x7e, 0x24, 0xc9,    \
  0xdb, 0xfb, 0x36, 0x7c, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,    \
  0x3d, 0x04, 0x03, 0x02, 0x05, 0x00, 0x03, 0x68, 0x00, 0x30, 0x65, 0x02,    \
  0x30, 0x51, 0xca, 0xae, 0x30, 0x0f, 0xa4, 0x70, 0x74, 0x04, 0xdd, 0x5a,    \
  0x2c, 0x7f, 0x13, 0xc1, 0xc2, 0x77, 0xbe, 0x1d, 0x00, 0xc5, 0xe2, 0x99,    \
  0x8f, 0x7d, 0x26, 0x45, 0xd3, 0x8a, 0x06, 0x68, 0x3f, 0x8c, 0xb4, 0xb7,    \
  0xad, 0x4d, 0xe0, 0xf1, 0x54, 0x01, 0x1e, 0x99, 0xfc, 0xb0, 0xe4, 0xd3,    \
  0x07, 0x02, 0x31, 0x00, 0xdc, 0x4f, 0x3b, 0x90, 0x1e, 0xae, 0x29, 0x99,    \
  0x84, 0x28, 0xcc, 0x7b, 0x47, 0x78, 0x09, 0x31, 0xdf, 0xd6, 0x01, 0x59,    \
  0x30, 0x5e, 0xf4, 0xf8, 0x8a, 0x84, 0x3f, 0xea, 0x39, 0x54, 0x7b, 0x08,    \
  0xa7, 0x60, 0xaa, 0xbd, 0xf9, 0x5b, 0xd1, 0x51, 0x96, 0x14, 0x2e, 0x65,    \
  0xf5, 0xae, 0x1c, 0x42                                                     \
}
/* END FILE */

/* This is taken from tests/data_files/test-ca2.key.enc */
/* BEGIN FILE string macro TEST_CA_KEY_EC_PEM tests/data_files/test-ca2.key.enc */
#define TEST_CA_KEY_EC_PEM                                                 \
    "-----BEGIN EC PRIVATE KEY-----\r\n"                                   \
    "Proc-Type: 4,ENCRYPTED\r\n"                                           \
    "DEK-Info: DES-EDE3-CBC,307EAB469933D64E\r\n"                          \
    "\r\n"                                                                 \
    "IxbrRmKcAzctJqPdTQLA4SWyBYYGYJVkYEna+F7Pa5t5Yg/gKADrFKcm6B72e7DG\r\n" \
    "ihExtZI648s0zdYw6qSJ74vrPSuWDe5qm93BqsfVH9svtCzWHW0pm1p0KTBCFfUq\r\n" \
    "UsuWTITwJImcnlAs1gaRZ3sAWm7cOUidL0fo2G0fYUFNcYoCSLffCFTEHBuPnagb\r\n" \
    "a77x/sY1Bvii8S9/XhDTb6pTMx06wzrm\r\n"                                 \
    "-----END EC PRIVATE KEY-----\r\n"
/* END FILE */

#define TEST_CA_PWD_EC_PEM "PolarSSLTest"

/* This is generated from tests/data_files/test-ca2.key.der using `xxd -i`. */
/* BEGIN FILE binary macro TEST_CA_KEY_EC_DER tests/data_files/test-ca2.key.der */
#define TEST_CA_KEY_EC_DER {                                                 \
    0x30, 0x81, 0xa4, 0x02, 0x01, 0x01, 0x04, 0x30, 0x83, 0xd9, 0x15, 0x0e,  \
    0xa0, 0x71, 0xf0, 0x57, 0x10, 0x33, 0xa3, 0x38, 0xb8, 0x86, 0xc1, 0xa6,  \
    0x11, 0x5d, 0x6d, 0xb4, 0x03, 0xe1, 0x29, 0x76, 0x45, 0xd7, 0x87, 0x6f,  \
    0x23, 0xab, 0x44, 0x20, 0xea, 0x64, 0x7b, 0x85, 0xb1, 0x76, 0xe7, 0x85,  \
    0x95, 0xaa, 0x74, 0xd6, 0xd1, 0xa4, 0x5e, 0xea, 0xa0, 0x07, 0x06, 0x05,  \
    0x2b, 0x81, 0x04, 0x00, 0x22, 0xa1, 0x64, 0x03, 0x62, 0x00, 0x04, 0xc3,  \
    0xda, 0x2b, 0x34, 0x41, 0x37, 0x58, 0x2f, 0x87, 0x56, 0xfe, 0xfc, 0x89,  \
    0xba, 0x29, 0x43, 0x4b, 0x4e, 0xe0, 0x6e, 0xc3, 0x0e, 0x57, 0x53, 0x33,  \
    0x39, 0x58, 0xd4, 0x52, 0xb4, 0x91, 0x95, 0x39, 0x0b, 0x23, 0xdf, 0x5f,  \
    0x17, 0x24, 0x62, 0x48, 0xfc, 0x1a, 0x95, 0x29, 0xce, 0x2c, 0x2d, 0x87,  \
    0xc2, 0x88, 0x52, 0x80, 0xaf, 0xd6, 0x6a, 0xab, 0x21, 0xdd, 0xb8, 0xd3,  \
    0x1c, 0x6e, 0x58, 0xb8, 0xca, 0xe8, 0xb2, 0x69, 0x8e, 0xf3, 0x41, 0xad,  \
    0x29, 0xc3, 0xb4, 0x5f, 0x75, 0xa7, 0x47, 0x6f, 0xd5, 0x19, 0x29, 0x55,  \
    0x69, 0x9a, 0x53, 0x3b, 0x20, 0xb4, 0x66, 0x16, 0x60, 0x33, 0x1e         \
}
/* END FILE */

/* This is taken from tests/data_files/test-ca-sha256.crt. */
/* BEGIN FILE string macro TEST_CA_CRT_RSA_SHA256_PEM tests/data_files/test-ca-sha256.crt */
#define TEST_CA_CRT_RSA_SHA256_PEM                                         \
    "-----BEGIN CERTIFICATE-----\r\n"                                      \
    "MIIDQTCCAimgAwIBAgIBAzANBgkqhkiG9w0BAQsFADA7MQswCQYDVQQGEwJOTDER\r\n" \
    "MA8GA1UECgwIUG9sYXJTU0wxGTAXBgNVBAMMEFBvbGFyU1NMIFRlc3QgQ0EwHhcN\r\n" \
    "MTkwMjEwMTQ0NDAwWhcNMjkwMjEwMTQ0NDAwWjA7MQswCQYDVQQGEwJOTDERMA8G\r\n" \
    "A1UECgwIUG9sYXJTU0wxGTAXBgNVBAMMEFBvbGFyU1NMIFRlc3QgQ0EwggEiMA0G\r\n" \
    "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDA3zf8F7vglp0/ht6WMn1EpRagzSHx\r\n" \
    "mdTs6st8GFgIlKXsm8WL3xoemTiZhx57wI053zhdcHgH057Zk+i5clHFzqMwUqny\r\n" \
    "50BwFMtEonILwuVA+T7lpg6z+exKY8C4KQB0nFc7qKUEkHHxvYPZP9al4jwqj+8n\r\n" \
    "YMPGn8u67GB9t+aEMr5P+1gmIgNb1LTV+/Xjli5wwOQuvfwu7uJBVcA0Ln0kcmnL\r\n" \
    "R7EUQIN9Z/SG9jGr8XmksrUuEvmEF/Bibyc+E1ixVA0hmnM3oTDPb5Lc9un8rNsu\r\n" \
    "KNF+AksjoBXyOGVkCeoMbo4bF6BxyLObyavpw/LPh5aPgAIynplYb6LVAgMBAAGj\r\n" \
    "UDBOMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFLRa5KWz3tJS9rnVppUP6z68x/3/\r\n" \
    "MB8GA1UdIwQYMBaAFLRa5KWz3tJS9rnVppUP6z68x/3/MA0GCSqGSIb3DQEBCwUA\r\n" \
    "A4IBAQA4qFSCth2q22uJIdE4KGHJsJjVEfw2/xn+MkTvCMfxVrvmRvqCtjE4tKDl\r\n" \
    "oK4MxFOek07oDZwvtAT9ijn1hHftTNS7RH9zd/fxNpfcHnMZXVC4w4DNA1fSANtW\r\n" \
    "5sY1JB5Je9jScrsLSS+mAjyv0Ow3Hb2Bix8wu7xNNrV5fIf7Ubm+wt6SqEBxu3Kb\r\n" \
    "+EfObAT4huf3czznhH3C17ed6NSbXwoXfby7stWUDeRJv08RaFOykf/Aae7bY5PL\r\n" \
    "yTVrkAnikMntJ9YI+hNNYt3inqq11A5cN0+rVTst8UKCxzQ4GpvroSwPKTFkbMw4\r\n" \
    "/anT1dVxr/BtwJfiESoK3/4CeXR1\r\n"                                     \
    "-----END CERTIFICATE-----\r\n"
/* END FILE */

/* This is generated from tests/data_files/test-ca-sha256.crt.der
 * using `xxd -i`. */
/* BEGIN FILE binary macro TEST_CA_CRT_RSA_SHA256_DER tests/data_files/test-ca-sha256.crt.der */
#define TEST_CA_CRT_RSA_SHA256_DER {                                         \
  0x30, 0x82, 0x03, 0x41, 0x30, 0x82, 0x02, 0x29, 0xa0, 0x03, 0x02, 0x01,    \
  0x02, 0x02, 0x01, 0x03, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,    \
  0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x3b, 0x31, 0x0b, 0x30,    \
  0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11,    \
  0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c,    \
  0x61, 0x72, 0x53, 0x53, 0x4c, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55,    \
  0x04, 0x03, 0x0c, 0x10, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c,    \
  0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d,    \
  0x31, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34, 0x34, 0x30, 0x30,    \
  0x5a, 0x17, 0x0d, 0x32, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34,    \
  0x34, 0x30, 0x30, 0x5a, 0x30, 0x3b, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,    \
  0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, 0x30, 0x0f, 0x06,    \
  0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53,    \
  0x53, 0x4c, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,    \
  0x10, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c, 0x20, 0x54, 0x65,    \
  0x73, 0x74, 0x20, 0x43, 0x41, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06,    \
  0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,    \
  0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01,    \
  0x01, 0x00, 0xc0, 0xdf, 0x37, 0xfc, 0x17, 0xbb, 0xe0, 0x96, 0x9d, 0x3f,    \
  0x86, 0xde, 0x96, 0x32, 0x7d, 0x44, 0xa5, 0x16, 0xa0, 0xcd, 0x21, 0xf1,    \
  0x99, 0xd4, 0xec, 0xea, 0xcb, 0x7c, 0x18, 0x58, 0x08, 0x94, 0xa5, 0xec,    \
  0x9b, 0xc5, 0x8b, 0xdf, 0x1a, 0x1e, 0x99, 0x38, 0x99, 0x87, 0x1e, 0x7b,    \
  0xc0, 0x8d, 0x39, 0xdf, 0x38, 0x5d, 0x70, 0x78, 0x07, 0xd3, 0x9e, 0xd9,    \
  0x93, 0xe8, 0xb9, 0x72, 0x51, 0xc5, 0xce, 0xa3, 0x30, 0x52, 0xa9, 0xf2,    \
  0xe7, 0x40, 0x70, 0x14, 0xcb, 0x44, 0xa2, 0x72, 0x0b, 0xc2, 0xe5, 0x40,    \
  0xf9, 0x3e, 0xe5, 0xa6, 0x0e, 0xb3, 0xf9, 0xec, 0x4a, 0x63, 0xc0, 0xb8,    \
  0x29, 0x00, 0x74, 0x9c, 0x57, 0x3b, 0xa8, 0xa5, 0x04, 0x90, 0x71, 0xf1,    \
  0xbd, 0x83, 0xd9, 0x3f, 0xd6, 0xa5, 0xe2, 0x3c, 0x2a, 0x8f, 0xef, 0x27,    \
  0x60, 0xc3, 0xc6, 0x9f, 0xcb, 0xba, 0xec, 0x60, 0x7d, 0xb7, 0xe6, 0x84,    \
  0x32, 0xbe, 0x4f, 0xfb, 0x58, 0x26, 0x22, 0x03, 0x5b, 0xd4, 0xb4, 0xd5,    \
  0xfb, 0xf5, 0xe3, 0x96, 0x2e, 0x70, 0xc0, 0xe4, 0x2e, 0xbd, 0xfc, 0x2e,    \
  0xee, 0xe2, 0x41, 0x55, 0xc0, 0x34, 0x2e, 0x7d, 0x24, 0x72, 0x69, 0xcb,    \
  0x47, 0xb1, 0x14, 0x40, 0x83, 0x7d, 0x67, 0xf4, 0x86, 0xf6, 0x31, 0xab,    \
  0xf1, 0x79, 0xa4, 0xb2, 0xb5, 0x2e, 0x12, 0xf9, 0x84, 0x17, 0xf0, 0x62,    \
  0x6f, 0x27, 0x3e, 0x13, 0x58, 0xb1, 0x54, 0x0d, 0x21, 0x9a, 0x73, 0x37,    \
  0xa1, 0x30, 0xcf, 0x6f, 0x92, 0xdc, 0xf6, 0xe9, 0xfc, 0xac, 0xdb, 0x2e,    \
  0x28, 0xd1, 0x7e, 0x02, 0x4b, 0x23, 0xa0, 0x15, 0xf2, 0x38, 0x65, 0x64,    \
  0x09, 0xea, 0x0c, 0x6e, 0x8e, 0x1b, 0x17, 0xa0, 0x71, 0xc8, 0xb3, 0x9b,    \
  0xc9, 0xab, 0xe9, 0xc3, 0xf2, 0xcf, 0x87, 0x96, 0x8f, 0x80, 0x02, 0x32,    \
  0x9e, 0x99, 0x58, 0x6f, 0xa2, 0xd5, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3,    \
  0x50, 0x30, 0x4e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05,    \
  0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e,    \
  0x04, 0x16, 0x04, 0x14, 0xb4, 0x5a, 0xe4, 0xa5, 0xb3, 0xde, 0xd2, 0x52,    \
  0xf6, 0xb9, 0xd5, 0xa6, 0x95, 0x0f, 0xeb, 0x3e, 0xbc, 0xc7, 0xfd, 0xff,    \
  0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80,    \
  0x14, 0xb4, 0x5a, 0xe4, 0xa5, 0xb3, 0xde, 0xd2, 0x52, 0xf6, 0xb9, 0xd5,    \
  0xa6, 0x95, 0x0f, 0xeb, 0x3e, 0xbc, 0xc7, 0xfd, 0xff, 0x30, 0x0d, 0x06,    \
  0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,    \
  0x03, 0x82, 0x01, 0x01, 0x00, 0x38, 0xa8, 0x54, 0x82, 0xb6, 0x1d, 0xaa,    \
  0xdb, 0x6b, 0x89, 0x21, 0xd1, 0x38, 0x28, 0x61, 0xc9, 0xb0, 0x98, 0xd5,    \
  0x11, 0xfc, 0x36, 0xff, 0x19, 0xfe, 0x32, 0x44, 0xef, 0x08, 0xc7, 0xf1,    \
  0x56, 0xbb, 0xe6, 0x46, 0xfa, 0x82, 0xb6, 0x31, 0x38, 0xb4, 0xa0, 0xe5,    \
  0xa0, 0xae, 0x0c, 0xc4, 0x53, 0x9e, 0x93, 0x4e, 0xe8, 0x0d, 0x9c, 0x2f,    \
  0xb4, 0x04, 0xfd, 0x8a, 0x39, 0xf5, 0x84, 0x77, 0xed, 0x4c, 0xd4, 0xbb,    \
  0x44, 0x7f, 0x73, 0x77, 0xf7, 0xf1, 0x36, 0x97, 0xdc, 0x1e, 0x73, 0x19,    \
  0x5d, 0x50, 0xb8, 0xc3, 0x80, 0xcd, 0x03, 0x57, 0xd2, 0x00, 0xdb, 0x56,    \
  0xe6, 0xc6, 0x35, 0x24, 0x1e, 0x49, 0x7b, 0xd8, 0xd2, 0x72, 0xbb, 0x0b,    \
  0x49, 0x2f, 0xa6, 0x02, 0x3c, 0xaf, 0xd0, 0xec, 0x37, 0x1d, 0xbd, 0x81,    \
  0x8b, 0x1f, 0x30, 0xbb, 0xbc, 0x4d, 0x36, 0xb5, 0x79, 0x7c, 0x87, 0xfb,    \
  0x51, 0xb9, 0xbe, 0xc2, 0xde, 0x92, 0xa8, 0x40, 0x71, 0xbb, 0x72, 0x9b,    \
  0xf8, 0x47, 0xce, 0x6c, 0x04, 0xf8, 0x86, 0xe7, 0xf7, 0x73, 0x3c, 0xe7,    \
  0x84, 0x7d, 0xc2, 0xd7, 0xb7, 0x9d, 0xe8, 0xd4, 0x9b, 0x5f, 0x0a, 0x17,    \
  0x7d, 0xbc, 0xbb, 0xb2, 0xd5, 0x94, 0x0d, 0xe4, 0x49, 0xbf, 0x4f, 0x11,    \
  0x68, 0x53, 0xb2, 0x91, 0xff, 0xc0, 0x69, 0xee, 0xdb, 0x63, 0x93, 0xcb,    \
  0xc9, 0x35, 0x6b, 0x90, 0x09, 0xe2, 0x90, 0xc9, 0xed, 0x27, 0xd6, 0x08,    \
  0xfa, 0x13, 0x4d, 0x62, 0xdd, 0xe2, 0x9e, 0xaa, 0xb5, 0xd4, 0x0e, 0x5c,    \
  0x37, 0x4f, 0xab, 0x55, 0x3b, 0x2d, 0xf1, 0x42, 0x82, 0xc7, 0x34, 0x38,    \
  0x1a, 0x9b, 0xeb, 0xa1, 0x2c, 0x0f, 0x29, 0x31, 0x64, 0x6c, 0xcc, 0x38,    \
  0xfd, 0xa9, 0xd3, 0xd5, 0xd5, 0x71, 0xaf, 0xf0, 0x6d, 0xc0, 0x97, 0xe2,    \
  0x11, 0x2a, 0x0a, 0xdf, 0xfe, 0x02, 0x79, 0x74, 0x75                       \
}
/* END FILE */

/* This is taken from tests/data_files/test-ca-sha1.crt. */
/* BEGIN FILE string macro TEST_CA_CRT_RSA_SHA1_PEM tests/data_files/test-ca-sha1.crt */
#define TEST_CA_CRT_RSA_SHA1_PEM                                           \
    "-----BEGIN CERTIFICATE-----\r\n"                                      \
    "MIIDQTCCAimgAwIBAgIBAzANBgkqhkiG9w0BAQUFADA7MQswCQYDVQQGEwJOTDER\r\n" \
    "MA8GA1UECgwIUG9sYXJTU0wxGTAXBgNVBAMMEFBvbGFyU1NMIFRlc3QgQ0EwHhcN\r\n" \
    "MTkwMjEwMTQ0NDAwWhcNMjkwMjEwMTQ0NDAwWjA7MQswCQYDVQQGEwJOTDERMA8G\r\n" \
    "A1UECgwIUG9sYXJTU0wxGTAXBgNVBAMMEFBvbGFyU1NMIFRlc3QgQ0EwggEiMA0G\r\n" \
    "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDA3zf8F7vglp0/ht6WMn1EpRagzSHx\r\n" \
    "mdTs6st8GFgIlKXsm8WL3xoemTiZhx57wI053zhdcHgH057Zk+i5clHFzqMwUqny\r\n" \
    "50BwFMtEonILwuVA+T7lpg6z+exKY8C4KQB0nFc7qKUEkHHxvYPZP9al4jwqj+8n\r\n" \
    "YMPGn8u67GB9t+aEMr5P+1gmIgNb1LTV+/Xjli5wwOQuvfwu7uJBVcA0Ln0kcmnL\r\n" \
    "R7EUQIN9Z/SG9jGr8XmksrUuEvmEF/Bibyc+E1ixVA0hmnM3oTDPb5Lc9un8rNsu\r\n" \
    "KNF+AksjoBXyOGVkCeoMbo4bF6BxyLObyavpw/LPh5aPgAIynplYb6LVAgMBAAGj\r\n" \
    "UDBOMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFLRa5KWz3tJS9rnVppUP6z68x/3/\r\n" \
    "MB8GA1UdIwQYMBaAFLRa5KWz3tJS9rnVppUP6z68x/3/MA0GCSqGSIb3DQEBBQUA\r\n" \
    "A4IBAQB0ZiNRFdia6kskaPnhrqejIRq8YMEGAf2oIPnyZ78xoyERgc35lHGyMtsL\r\n" \
    "hWicNjP4d/hS9As4j5KA2gdNGi5ETA1X7SowWOGsryivSpMSHVy1+HdfWlsYQOzm\r\n" \
    "8o+faQNUm8XzPVmttfAVspxeHSxJZ36Oo+QWZ5wZlCIEyjEdLUId+Tm4Bz3B5jRD\r\n" \
    "zZa/SaqDokq66N2zpbgKKAl3GU2O++fBqP2dSkdQykmTxhLLWRN8FJqhYATyQntZ\r\n" \
    "0QSi3W9HfSZPnFTcPIXeoiPd2pLlxt1hZu8dws2LTXE63uP6MM4LHvWxiuJaWkP/\r\n" \
    "mtxyUALj2pQxRitopORFQdn7AOY5\r\n"                                     \
    "-----END CERTIFICATE-----\r\n"
/* END FILE */

/* This is taken from tests/data_files/test-ca-sha1.crt.der. */
/* BEGIN FILE binary macro TEST_CA_CRT_RSA_SHA1_DER tests/data_files/test-ca-sha1.crt.der */
#define TEST_CA_CRT_RSA_SHA1_DER {                                           \
  0x30, 0x82, 0x03, 0x41, 0x30, 0x82, 0x02, 0x29, 0xa0, 0x03, 0x02, 0x01,    \
  0x02, 0x02, 0x01, 0x03, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,    \
  0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x3b, 0x31, 0x0b, 0x30,    \
  0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11,    \
  0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c,    \
  0x61, 0x72, 0x53, 0x53, 0x4c, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55,    \
  0x04, 0x03, 0x0c, 0x10, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c,    \
  0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d,    \
  0x31, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34, 0x34, 0x30, 0x30,    \
  0x5a, 0x17, 0x0d, 0x32, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34,    \
  0x34, 0x30, 0x30, 0x5a, 0x30, 0x3b, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,    \
  0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, 0x30, 0x0f, 0x06,    \
  0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53,    \
  0x53, 0x4c, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,    \
  0x10, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c, 0x20, 0x54, 0x65,    \
  0x73, 0x74, 0x20, 0x43, 0x41, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06,    \
  0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,    \
  0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01,    \
  0x01, 0x00, 0xc0, 0xdf, 0x37, 0xfc, 0x17, 0xbb, 0xe0, 0x96, 0x9d, 0x3f,    \
  0x86, 0xde, 0x96, 0x32, 0x7d, 0x44, 0xa5, 0x16, 0xa0, 0xcd, 0x21, 0xf1,    \
  0x99, 0xd4, 0xec, 0xea, 0xcb, 0x7c, 0x18, 0x58, 0x08, 0x94, 0xa5, 0xec,    \
  0x9b, 0xc5, 0x8b, 0xdf, 0x1a, 0x1e, 0x99, 0x38, 0x99, 0x87, 0x1e, 0x7b,    \
  0xc0, 0x8d, 0x39, 0xdf, 0x38, 0x5d, 0x70, 0x78, 0x07, 0xd3, 0x9e, 0xd9,    \
  0x93, 0xe8, 0xb9, 0x72, 0x51, 0xc5, 0xce, 0xa3, 0x30, 0x52, 0xa9, 0xf2,    \
  0xe7, 0x40, 0x70, 0x14, 0xcb, 0x44, 0xa2, 0x72, 0x0b, 0xc2, 0xe5, 0x40,    \
  0xf9, 0x3e, 0xe5, 0xa6, 0x0e, 0xb3, 0xf9, 0xec, 0x4a, 0x63, 0xc0, 0xb8,    \
  0x29, 0x00, 0x74, 0x9c, 0x57, 0x3b, 0xa8, 0xa5, 0x04, 0x90, 0x71, 0xf1,    \
  0xbd, 0x83, 0xd9, 0x3f, 0xd6, 0xa5, 0xe2, 0x3c, 0x2a, 0x8f, 0xef, 0x27,    \
  0x60, 0xc3, 0xc6, 0x9f, 0xcb, 0xba, 0xec, 0x60, 0x7d, 0xb7, 0xe6, 0x84,    \
  0x32, 0xbe, 0x4f, 0xfb, 0x58, 0x26, 0x22, 0x03, 0x5b, 0xd4, 0xb4, 0xd5,    \
  0xfb, 0xf5, 0xe3, 0x96, 0x2e, 0x70, 0xc0, 0xe4, 0x2e, 0xbd, 0xfc, 0x2e,    \
  0xee, 0xe2, 0x41, 0x55, 0xc0, 0x34, 0x2e, 0x7d, 0x24, 0x72, 0x69, 0xcb,    \
  0x47, 0xb1, 0x14, 0x40, 0x83, 0x7d, 0x67, 0xf4, 0x86, 0xf6, 0x31, 0xab,    \
  0xf1, 0x79, 0xa4, 0xb2, 0xb5, 0x2e, 0x12, 0xf9, 0x84, 0x17, 0xf0, 0x62,    \
  0x6f, 0x27, 0x3e, 0x13, 0x58, 0xb1, 0x54, 0x0d, 0x21, 0x9a, 0x73, 0x37,    \
  0xa1, 0x30, 0xcf, 0x6f, 0x92, 0xdc, 0xf6, 0xe9, 0xfc, 0xac, 0xdb, 0x2e,    \
  0x28, 0xd1, 0x7e, 0x02, 0x4b, 0x23, 0xa0, 0x15, 0xf2, 0x38, 0x65, 0x64,    \
  0x09, 0xea, 0x0c, 0x6e, 0x8e, 0x1b, 0x17, 0xa0, 0x71, 0xc8, 0xb3, 0x9b,    \
  0xc9, 0xab, 0xe9, 0xc3, 0xf2, 0xcf, 0x87, 0x96, 0x8f, 0x80, 0x02, 0x32,    \
  0x9e, 0x99, 0x58, 0x6f, 0xa2, 0xd5, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3,    \
  0x50, 0x30, 0x4e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05,    \
  0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e,    \
  0x04, 0x16, 0x04, 0x14, 0xb4, 0x5a, 0xe4, 0xa5, 0xb3, 0xde, 0xd2, 0x52,    \
  0xf6, 0xb9, 0xd5, 0xa6, 0x95, 0x0f, 0xeb, 0x3e, 0xbc, 0xc7, 0xfd, 0xff,    \
  0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80,    \
  0x14, 0xb4, 0x5a, 0xe4, 0xa5, 0xb3, 0xde, 0xd2, 0x52, 0xf6, 0xb9, 0xd5,    \
  0xa6, 0x95, 0x0f, 0xeb, 0x3e, 0xbc, 0xc7, 0xfd, 0xff, 0x30, 0x0d, 0x06,    \
  0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00,    \
  0x03, 0x82, 0x01, 0x01, 0x00, 0x74, 0x66, 0x23, 0x51, 0x15, 0xd8, 0x9a,    \
  0xea, 0x4b, 0x24, 0x68, 0xf9, 0xe1, 0xae, 0xa7, 0xa3, 0x21, 0x1a, 0xbc,    \
  0x60, 0xc1, 0x06, 0x01, 0xfd, 0xa8, 0x20, 0xf9, 0xf2, 0x67, 0xbf, 0x31,    \
  0xa3, 0x21, 0x11, 0x81, 0xcd, 0xf9, 0x94, 0x71, 0xb2, 0x32, 0xdb, 0x0b,    \
  0x85, 0x68, 0x9c, 0x36, 0x33, 0xf8, 0x77, 0xf8, 0x52, 0xf4, 0x0b, 0x38,    \
  0x8f, 0x92, 0x80, 0xda, 0x07, 0x4d, 0x1a, 0x2e, 0x44, 0x4c, 0x0d, 0x57,    \
  0xed, 0x2a, 0x30, 0x58, 0xe1, 0xac, 0xaf, 0x28, 0xaf, 0x4a, 0x93, 0x12,    \
  0x1d, 0x5c, 0xb5, 0xf8, 0x77, 0x5f, 0x5a, 0x5b, 0x18, 0x40, 0xec, 0xe6,    \
  0xf2, 0x8f, 0x9f, 0x69, 0x03, 0x54, 0x9b, 0xc5, 0xf3, 0x3d, 0x59, 0xad,    \
  0xb5, 0xf0, 0x15, 0xb2, 0x9c, 0x5e, 0x1d, 0x2c, 0x49, 0x67, 0x7e, 0x8e,    \
  0xa3, 0xe4, 0x16, 0x67, 0x9c, 0x19, 0x94, 0x22, 0x04, 0xca, 0x31, 0x1d,    \
  0x2d, 0x42, 0x1d, 0xf9, 0x39, 0xb8, 0x07, 0x3d, 0xc1, 0xe6, 0x34, 0x43,    \
  0xcd, 0x96, 0xbf, 0x49, 0xaa, 0x83, 0xa2, 0x4a, 0xba, 0xe8, 0xdd, 0xb3,    \
  0xa5, 0xb8, 0x0a, 0x28, 0x09, 0x77, 0x19, 0x4d, 0x8e, 0xfb, 0xe7, 0xc1,    \
  0xa8, 0xfd, 0x9d, 0x4a, 0x47, 0x50, 0xca, 0x49, 0x93, 0xc6, 0x12, 0xcb,    \
  0x59, 0x13, 0x7c, 0x14, 0x9a, 0xa1, 0x60, 0x04, 0xf2, 0x42, 0x7b, 0x59,    \
  0xd1, 0x04, 0xa2, 0xdd, 0x6f, 0x47, 0x7d, 0x26, 0x4f, 0x9c, 0x54, 0xdc,    \
  0x3c, 0x85, 0xde, 0xa2, 0x23, 0xdd, 0xda, 0x92, 0xe5, 0xc6, 0xdd, 0x61,    \
  0x66, 0xef, 0x1d, 0xc2, 0xcd, 0x8b, 0x4d, 0x71, 0x3a, 0xde, 0xe3, 0xfa,    \
  0x30, 0xce, 0x0b, 0x1e, 0xf5, 0xb1, 0x8a, 0xe2, 0x5a, 0x5a, 0x43, 0xff,    \
  0x9a, 0xdc, 0x72, 0x50, 0x02, 0xe3, 0xda, 0x94, 0x31, 0x46, 0x2b, 0x68,    \
  0xa4, 0xe4, 0x45, 0x41, 0xd9, 0xfb, 0x00, 0xe6, 0x39                       \
}
/* END FILE */

/* This is taken from tests/data_files/test-ca.key */
/* BEGIN FILE string macro TEST_CA_KEY_RSA_PEM tests/data_files/test-ca.key */
#define TEST_CA_KEY_RSA_PEM                                                \
    "-----BEGIN RSA PRIVATE KEY-----\r\n"                                  \
    "Proc-Type: 4,ENCRYPTED\r\n"                                           \
    "DEK-Info: DES-EDE3-CBC,A8A95B05D5B7206B\r\n"                          \
    "\r\n"                                                                 \
    "9Qd9GeArejl1GDVh2lLV1bHt0cPtfbh5h/5zVpAVaFpqtSPMrElp50Rntn9et+JA\r\n" \
    "7VOyboR+Iy2t/HU4WvA687k3Bppe9GwKHjHhtl//8xFKwZr3Xb5yO5JUP8AUctQq\r\n" \
    "Nb8CLlZyuUC+52REAAthdWgsX+7dJO4yabzUcQ22Tp9JSD0hiL43BlkWYUNK3dAo\r\n" \
    "PZlmiptjnzVTjg1MxsBSydZinWOLBV8/JQgxSPo2yD4uEfig28qbvQ2wNIn0pnAb\r\n" \
    "GxnSAOazkongEGfvcjIIs+LZN9gXFhxcOh6kc4Q/c99B7QWETwLLkYgZ+z1a9VY9\r\n" \
    "gEU7CwCxYCD+h9hY6FPmsK0/lC4O7aeRKpYq00rPPxs6i7phiexg6ax6yTMmArQq\r\n" \
    "QmK3TAsJm8V/J5AWpLEV6jAFgRGymGGHnof0DXzVWZidrcZJWTNuGEX90nB3ee2w\r\n" \
    "PXJEFWKoD3K3aFcSLdHYr3mLGxP7H9ThQai9VsycxZKS5kwvBKQ//YMrmFfwPk8x\r\n" \
    "vTeY4KZMaUrveEel5tWZC94RSMKgxR6cyE1nBXyTQnDOGbfpNNgBKxyKbINWoOJU\r\n" \
    "WJZAwlsQn+QzCDwpri7+sV1mS3gBE6UY7aQmnmiiaC2V3Hbphxct/en5QsfDOt1X\r\n" \
    "JczSfpRWLlbPznZg8OQh/VgCMA58N5DjOzTIK7sJJ5r+94ZBTCpgAMbF588f0NTR\r\n" \
    "KCe4yrxGJR7X02M4nvD4IwOlpsQ8xQxZtOSgXv4LkxvdU9XJJKWZ/XNKJeWztxSe\r\n" \
    "Z1vdTc2YfsDBA2SEv33vxHx2g1vqtw8SjDRT2RaQSS0QuSaMJimdOX6mTOCBKk1J\r\n" \
    "9Q5mXTrER+/LnK0jEmXsBXWA5bqqVZIyahXSx4VYZ7l7w/PHiUDtDgyRhMMKi4n2\r\n" \
    "iQvQcWSQTjrpnlJbca1/DkpRt3YwrvJwdqb8asZU2VrNETh5x0QVefDRLFiVpif/\r\n" \
    "tUaeAe/P1F8OkS7OIZDs1SUbv/sD2vMbhNkUoCms3/PvNtdnvgL4F0zhaDpKCmlT\r\n" \
    "P8vx49E7v5CyRNmED9zZg4o3wmMqrQO93PtTug3Eu9oVx1zPQM1NVMyBa2+f29DL\r\n" \
    "1nuTCeXdo9+ni45xx+jAI4DCwrRdhJ9uzZyC6962H37H6D+5naNvClFR1s6li1Gb\r\n" \
    "nqPoiy/OBsEx9CaDGcqQBp5Wme/3XW+6z1ISOx+igwNTVCT14mHdBMbya0eIKft5\r\n" \
    "X+GnwtgEMyCYyyWuUct8g4RzErcY9+yW9Om5Hzpx4zOuW4NPZgPDTgK+t2RSL/Yq\r\n" \
    "rE1njrgeGYcVeG3f+OftH4s6fPbq7t1A5ZgUscbLMBqr9tK+OqygR4EgKBPsH6Cz\r\n" \
    "L6zlv/2RV0qAHvVuDJcIDIgwY5rJtINEm32rhOeFNJwZS5MNIC1czXZx5//ugX7l\r\n" \
    "I4sy5nbVhwSjtAk8Xg5dZbdTZ6mIrb7xqH+fdakZor1khG7bC2uIwibD3cSl2XkR\r\n" \
    "wN48lslbHnqqagr6Xm1nNOSVl8C/6kbJEsMpLhAezfRtGwvOucoaE+WbeUNolGde\r\n" \
    "P/eQiddSf0brnpiLJRh7qZrl9XuqYdpUqnoEdMAfotDOID8OtV7gt8a48ad8VPW2\r\n" \
    "-----END RSA PRIVATE KEY-----\r\n"
/* END FILE */

#define TEST_CA_PWD_RSA_PEM "PolarSSLTest"

/* This was generated from test-ca.key.der using `xxd -i`. */
/* BEGIN FILE binary macro TEST_CA_KEY_RSA_DER tests/data_files/test-ca.key.der */
#define TEST_CA_KEY_RSA_DER {                                                \
    0x30, 0x82, 0x04, 0xa4, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,  \
    0xc0, 0xdf, 0x37, 0xfc, 0x17, 0xbb, 0xe0, 0x96, 0x9d, 0x3f, 0x86, 0xde,  \
    0x96, 0x32, 0x7d, 0x44, 0xa5, 0x16, 0xa0, 0xcd, 0x21, 0xf1, 0x99, 0xd4,  \
    0xec, 0xea, 0xcb, 0x7c, 0x18, 0x58, 0x08, 0x94, 0xa5, 0xec, 0x9b, 0xc5,  \
    0x8b, 0xdf, 0x1a, 0x1e, 0x99, 0x38, 0x99, 0x87, 0x1e, 0x7b, 0xc0, 0x8d,  \
    0x39, 0xdf, 0x38, 0x5d, 0x70, 0x78, 0x07, 0xd3, 0x9e, 0xd9, 0x93, 0xe8,  \
    0xb9, 0x72, 0x51, 0xc5, 0xce, 0xa3, 0x30, 0x52, 0xa9, 0xf2, 0xe7, 0x40,  \
    0x70, 0x14, 0xcb, 0x44, 0xa2, 0x72, 0x0b, 0xc2, 0xe5, 0x40, 0xf9, 0x3e,  \
    0xe5, 0xa6, 0x0e, 0xb3, 0xf9, 0xec, 0x4a, 0x63, 0xc0, 0xb8, 0x29, 0x00,  \
    0x74, 0x9c, 0x57, 0x3b, 0xa8, 0xa5, 0x04, 0x90, 0x71, 0xf1, 0xbd, 0x83,  \
    0xd9, 0x3f, 0xd6, 0xa5, 0xe2, 0x3c, 0x2a, 0x8f, 0xef, 0x27, 0x60, 0xc3,  \
    0xc6, 0x9f, 0xcb, 0xba, 0xec, 0x60, 0x7d, 0xb7, 0xe6, 0x84, 0x32, 0xbe,  \
    0x4f, 0xfb, 0x58, 0x26, 0x22, 0x03, 0x5b, 0xd4, 0xb4, 0xd5, 0xfb, 0xf5,  \
    0xe3, 0x96, 0x2e, 0x70, 0xc0, 0xe4, 0x2e, 0xbd, 0xfc, 0x2e, 0xee, 0xe2,  \
    0x41, 0x55, 0xc0, 0x34, 0x2e, 0x7d, 0x24, 0x72, 0x69, 0xcb, 0x47, 0xb1,  \
    0x14, 0x40, 0x83, 0x7d, 0x67, 0xf4, 0x86, 0xf6, 0x31, 0xab, 0xf1, 0x79,  \
    0xa4, 0xb2, 0xb5, 0x2e, 0x12, 0xf9, 0x84, 0x17, 0xf0, 0x62, 0x6f, 0x27,  \
    0x3e, 0x13, 0x58, 0xb1, 0x54, 0x0d, 0x21, 0x9a, 0x73, 0x37, 0xa1, 0x30,  \
    0xcf, 0x6f, 0x92, 0xdc, 0xf6, 0xe9, 0xfc, 0xac, 0xdb, 0x2e, 0x28, 0xd1,  \
    0x7e, 0x02, 0x4b, 0x23, 0xa0, 0x15, 0xf2, 0x38, 0x65, 0x64, 0x09, 0xea,  \
    0x0c, 0x6e, 0x8e, 0x1b, 0x17, 0xa0, 0x71, 0xc8, 0xb3, 0x9b, 0xc9, 0xab,  \
    0xe9, 0xc3, 0xf2, 0xcf, 0x87, 0x96, 0x8f, 0x80, 0x02, 0x32, 0x9e, 0x99,  \
    0x58, 0x6f, 0xa2, 0xd5, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01,  \
    0x00, 0x3f, 0xf7, 0x07, 0xd3, 0x34, 0x6f, 0xdb, 0xc9, 0x37, 0xb7, 0x84,  \
    0xdc, 0x37, 0x45, 0xe1, 0x63, 0xad, 0xb8, 0xb6, 0x75, 0xb1, 0xc7, 0x35,  \
    0xb4, 0x77, 0x2a, 0x5b, 0x77, 0xf9, 0x7e, 0xe0, 0xc1, 0xa3, 0xd1, 0xb7,  \
    0xcb, 0xa9, 0x5a, 0xc1, 0x87, 0xda, 0x5a, 0xfa, 0x17, 0xe4, 0xd5, 0x38,  \
    0x03, 0xde, 0x68, 0x98, 0x81, 0xec, 0xb5, 0xf2, 0x2a, 0x8d, 0xe9, 0x2c,  \
    0xf3, 0xa6, 0xe5, 0x32, 0x17, 0x7f, 0x33, 0x81, 0xe8, 0x38, 0x72, 0xd5,  \
    0x9c, 0xfa, 0x4e, 0xfb, 0x26, 0xf5, 0x15, 0x0b, 0xaf, 0x84, 0x66, 0xab,  \
    0x02, 0xe0, 0x18, 0xd5, 0x91, 0x7c, 0xd6, 0x8f, 0xc9, 0x4b, 0x76, 0x08,  \
    0x2b, 0x1d, 0x81, 0x68, 0x30, 0xe1, 0xfa, 0x70, 0x6c, 0x13, 0x4e, 0x10,  \
    0x03, 0x35, 0x3e, 0xc5, 0xca, 0x58, 0x20, 0x8a, 0x21, 0x18, 0x38, 0xa0,  \
    0x0f, 0xed, 0xc4, 0xbb, 0x45, 0x6f, 0xf5, 0x84, 0x5b, 0xb0, 0xcf, 0x4e,  \
    0x9d, 0x58, 0x13, 0x6b, 0x35, 0x35, 0x69, 0xa1, 0xd2, 0xc4, 0xf2, 0xc1,  \
    0x48, 0x04, 0x20, 0x51, 0xb9, 0x6b, 0xa4, 0x5d, 0xa5, 0x4b, 0x84, 0x88,  \
    0x43, 0x48, 0x99, 0x2c, 0xbb, 0xa4, 0x97, 0xd6, 0xd6, 0x18, 0xf6, 0xec,  \
    0x5c, 0xd1, 0x31, 0x49, 0xc9, 0xf2, 0x8f, 0x0b, 0x4d, 0xef, 0x09, 0x02,  \
    0xfe, 0x7d, 0xfd, 0xbb, 0xaf, 0x2b, 0x83, 0x94, 0x22, 0xc4, 0xa7, 0x3e,  \
    0x66, 0xf5, 0xe0, 0x57, 0xdc, 0xf2, 0xed, 0x2c, 0x3e, 0x81, 0x74, 0x76,  \
    0x1e, 0x96, 0x6f, 0x74, 0x1e, 0x32, 0x0e, 0x14, 0x31, 0xd0, 0x74, 0xf0,  \
    0xf4, 0x07, 0xbd, 0xc3, 0xd1, 0x22, 0xc2, 0xa8, 0x95, 0x92, 0x06, 0x7f,  \
    0x43, 0x02, 0x91, 0xbc, 0xdd, 0x23, 0x01, 0x89, 0x94, 0x20, 0x44, 0x64,  \
    0xf5, 0x1d, 0x67, 0xd2, 0x8f, 0xe8, 0x69, 0xa5, 0x29, 0x25, 0xe6, 0x50,  \
    0x9c, 0xe3, 0xe9, 0xcb, 0x75, 0x02, 0x81, 0x81, 0x00, 0xe2, 0x29, 0x3e,  \
    0xaa, 0x6b, 0xd5, 0x59, 0x1e, 0x9c, 0xe6, 0x47, 0xd5, 0xb6, 0xd7, 0xe3,  \
    0xf1, 0x8e, 0x9e, 0xe9, 0x83, 0x5f, 0x10, 0x9f, 0x63, 0xec, 0x04, 0x44,  \
    0xcc, 0x3f, 0xf8, 0xd9, 0x3a, 0x17, 0xe0, 0x4f, 0xfe, 0xd8, 0x4d, 0xcd,  \
    0x46, 0x54, 0x74, 0xbf, 0x0a, 0xc4, 0x67, 0x9c, 0xa7, 0xd8, 0x89, 0x65,  \
    0x4c, 0xfd, 0x58, 0x2a, 0x47, 0x0f, 0xf4, 0x37, 0xb6, 0x55, 0xb0, 0x1d,  \
    0xed, 0xa7, 0x39, 0xfc, 0x4f, 0xa3, 0xc4, 0x75, 0x3a, 0xa3, 0x98, 0xa7,  \
    0x45, 0xf5, 0x66, 0xcb, 0x7c, 0x65, 0xfb, 0x80, 0x23, 0xe6, 0xff, 0xfd,  \
    0x99, 0x1f, 0x8e, 0x6b, 0xff, 0x5e, 0x93, 0x66, 0xdf, 0x6c, 0x6f, 0xc3,  \
    0xf6, 0x38, 0x2e, 0xff, 0x69, 0xb5, 0xac, 0xae, 0xbb, 0xc6, 0x71, 0x16,  \
    0x6b, 0xd0, 0xf8, 0x22, 0xd9, 0xf8, 0xa2, 0x72, 0x20, 0xd2, 0xe2, 0x3a,  \
    0x70, 0x4b, 0xde, 0xab, 0x2f, 0x02, 0x81, 0x81, 0x00, 0xda, 0x51, 0x9b,  \
    0xb8, 0xb2, 0x2a, 0x14, 0x75, 0x58, 0x40, 0x8d, 0x27, 0x70, 0xfa, 0x31,  \
    0x48, 0xb0, 0x20, 0x21, 0x34, 0xfa, 0x4c, 0x57, 0xa8, 0x11, 0x88, 0xf3,  \
    0xa7, 0xae, 0x21, 0xe9, 0xb6, 0x2b, 0xd1, 0xcd, 0xa7, 0xf8, 0xd8, 0x0c,  \
    0x8a, 0x76, 0x22, 0x35, 0x44, 0xce, 0x3f, 0x25, 0x29, 0x83, 0x7d, 0x79,  \
    0xa7, 0x31, 0xd6, 0xec, 0xb2, 0xbf, 0xda, 0x34, 0xb6, 0xf6, 0xb2, 0x3b,  \
    0xf3, 0x78, 0x5a, 0x04, 0x83, 0x33, 0x3e, 0xa2, 0xe2, 0x81, 0x82, 0x13,  \
    0xd4, 0x35, 0x17, 0x63, 0x9b, 0x9e, 0xc4, 0x8d, 0x91, 0x4c, 0x03, 0x77,  \
    0xc7, 0x71, 0x5b, 0xee, 0x83, 0x6d, 0xd5, 0x78, 0x88, 0xf6, 0x2c, 0x79,  \
    0xc2, 0x4a, 0xb4, 0x79, 0x90, 0x70, 0xbf, 0xdf, 0x34, 0x56, 0x96, 0x71,  \
    0xe3, 0x0e, 0x68, 0x91, 0xbc, 0xea, 0xcb, 0x33, 0xc0, 0xbe, 0x45, 0xd7,  \
    0xfc, 0x30, 0xfd, 0x01, 0x3b, 0x02, 0x81, 0x81, 0x00, 0xd2, 0x9f, 0x2a,  \
    0xb7, 0x38, 0x19, 0xc7, 0x17, 0x95, 0x73, 0x78, 0xae, 0xf5, 0xcb, 0x75,  \
    0x83, 0x7f, 0x19, 0x4b, 0xcb, 0x86, 0xfb, 0x4a, 0x15, 0x9a, 0xb6, 0x17,  \
    0x04, 0x49, 0x07, 0x8d, 0xf6, 0x66, 0x4a, 0x06, 0xf6, 0x05, 0xa7, 0xdf,  \
    0x66, 0x82, 0x3c, 0xff, 0xb6, 0x1d, 0x57, 0x89, 0x33, 0x5f, 0x9c, 0x05,  \
    0x75, 0x7f, 0xf3, 0x5d, 0xdc, 0x34, 0x65, 0x72, 0x85, 0x22, 0xa4, 0x14,  \
    0x1b, 0x41, 0xc3, 0xe4, 0xd0, 0x9e, 0x69, 0xd5, 0xeb, 0x38, 0x74, 0x70,  \
    0x43, 0xdc, 0xd9, 0x50, 0xe4, 0x97, 0x6d, 0x73, 0xd6, 0xfb, 0xc8, 0xa7,  \
    0xfa, 0xb4, 0xc2, 0xc4, 0x9d, 0x5d, 0x0c, 0xd5, 0x9f, 0x79, 0xb3, 0x54,  \
    0xc2, 0xb7, 0x6c, 0x3d, 0x7d, 0xcb, 0x2d, 0xf8, 0xc4, 0xf3, 0x78, 0x5a,  \
    0x33, 0x2a, 0xb8, 0x0c, 0x6d, 0x06, 0xfa, 0xf2, 0x62, 0xd3, 0x42, 0xd0,  \
    0xbd, 0xc8, 0x4a, 0xa5, 0x0d, 0x02, 0x81, 0x81, 0x00, 0xd4, 0xa9, 0x90,  \
    0x15, 0xde, 0xbf, 0x2c, 0xc4, 0x8d, 0x9d, 0xfb, 0xa1, 0xc2, 0xe4, 0x83,  \
    0xe3, 0x79, 0x65, 0x22, 0xd3, 0xb7, 0x49, 0x6c, 0x4d, 0x94, 0x1f, 0x22,  \
    0xb1, 0x60, 0xe7, 0x3a, 0x00, 0xb1, 0x38, 0xa2, 0xab, 0x0f, 0xb4, 0x6c,  \
    0xaa, 0xe7, 0x9e, 0x34, 0xe3, 0x7c, 0x40, 0x78, 0x53, 0xb2, 0xf9, 0x23,  \
    0xea, 0xa0, 0x9a, 0xea, 0x60, 0xc8, 0x8f, 0xa6, 0xaf, 0xdf, 0x29, 0x09,  \
    0x4b, 0x06, 0x1e, 0x31, 0xad, 0x17, 0xda, 0xd8, 0xd1, 0xe9, 0x33, 0xab,  \
    0x5b, 0x18, 0x08, 0x5b, 0x87, 0xf8, 0xa5, 0x1f, 0xfd, 0xbb, 0xdc, 0xd8,  \
    0xed, 0x97, 0x57, 0xe4, 0xc3, 0x73, 0xd6, 0xf0, 0x9e, 0x01, 0xa6, 0x9b,  \
    0x48, 0x8e, 0x7a, 0xb4, 0xbb, 0xe5, 0x88, 0x91, 0xc5, 0x2a, 0xdf, 0x4b,  \
    0xba, 0xd0, 0x8b, 0x3e, 0x03, 0x97, 0x77, 0x2f, 0x47, 0x7e, 0x51, 0x0c,  \
    0xae, 0x65, 0x8d, 0xde, 0x87, 0x02, 0x81, 0x80, 0x20, 0x24, 0x0f, 0xd2,  \
    0xaf, 0xc2, 0x28, 0x3b, 0x97, 0x20, 0xb2, 0x92, 0x49, 0xeb, 0x09, 0x68,  \
    0x40, 0xb2, 0xbe, 0xd1, 0xc3, 0x83, 0x94, 0x34, 0x38, 0xd6, 0xc9, 0xec,  \
    0x34, 0x09, 0xf9, 0x41, 0x6d, 0x5c, 0x42, 0x94, 0xf7, 0x04, 0xfc, 0x32,  \
    0x39, 0x69, 0xbc, 0x1c, 0xfb, 0x3e, 0x61, 0x98, 0xc0, 0x80, 0xd8, 0x36,  \
    0x47, 0xc3, 0x6d, 0xc2, 0x2e, 0xe7, 0x81, 0x2a, 0x17, 0x34, 0x64, 0x30,  \
    0x4e, 0x96, 0xbb, 0x26, 0x16, 0xb9, 0x41, 0x36, 0xfe, 0x8a, 0xd6, 0x53,  \
    0x7c, 0xaa, 0xec, 0x39, 0x42, 0x50, 0xef, 0xe3, 0xb3, 0x01, 0x28, 0x32,  \
    0xca, 0x6d, 0xf5, 0x9a, 0x1e, 0x9f, 0x37, 0xbe, 0xfe, 0x38, 0x20, 0x22,  \
    0x91, 0x8c, 0xcd, 0x95, 0x02, 0xf2, 0x4d, 0x6f, 0x1a, 0xb4, 0x43, 0xf0,  \
    0x19, 0xdf, 0x65, 0xc0, 0x92, 0xe7, 0x9d, 0x2f, 0x09, 0xe7, 0xec, 0x69,  \
    0xa8, 0xc2, 0x8f, 0x0d                                                   \
}
/* END FILE */

/*
 * Test server Certificates
 *
 * Test server certificates are defined for each choice
 * of the following parameters:
 * - PEM or DER encoding
 * - SHA-1 or SHA-256 hash
 * - RSA or EC key
 *
 * Things to add:
 * - multiple EC curve types
 */

/* This is taken from tests/data_files/server5.crt. */
/* BEGIN FILE string macro TEST_SRV_CRT_EC_PEM tests/data_files/server5.crt */
#define TEST_SRV_CRT_EC_PEM                                                \
  "-----BEGIN CERTIFICATE-----\r\n"	\
  "MIICNDCCAZWgAwIBAgIBATAMBggqhkjOPQQDAgUAMDYxGTAXBgNVBAMMEFJvb3Qg\r\n"	\
  "Q2VydGlmaWNhdGUxDDAKBgNVBAoMA1VvUzELMAkGA1UEBhMCVUswHhcNMjIwMTAx\r\n"	\
  "MDAwMDAwWhcNMjcwMTAxMDAwMDAwWjA4MRswGQYDVQQDDBJFbnRpdHkgQ2VydGlm\r\n"	\
  "aWNhdGUxDDAKBgNVBAoMA1VvUzELMAkGA1UEBhMCVUswgZswEAYHKoZIzj0CAQYF\r\n"	\
  "K4EEACMDgYYABAAUINv1t0sceo02BkY9lxGfVsilbQiEA9eoseMLEnp4qJukF8Yb\r\n"	\
  "0uJ4A/Ioj6if+OQI1Yhe+TMeLwzbPDMDNEgcywE7M6oka/mmTYv84KogodwPOHJx\r\n"	\
  "KWKPqlONIl/wpHiokNkKc6zY1nx5ts1zDbmRcixjrKlolcjFOSWlAxfTC9+HxqNN\r\n"	\
  "MEswCQYDVR0TBAIwADAdBgNVHQ4EFgQUQqsX/4zNZGGX8IRPbla2Ak1bLMkwHwYD\r\n"	\
  "VR0jBBgwFoAUzObtm+F3RSTZyX8hga4LQA21C8IwDAYIKoZIzj0EAwIFAAOBigAw\r\n"	\
  "gYYCQSUTi+jGRueKlXvE1aG+fhQmO9/dP8trHUUud0o8SKZj7wK6h0HFmHVBBFen\r\n"	\
  "Mlgx4wgK0kBw+9bO+RnsNPSGHmUVAkF76RKU+syXd1ZBn1fO5Dv1t3RCRI5zzVwJ\r\n"	\
  "Ln6zYQrZt6FgxDg6ALBxgHvNdRo/OC8MVmwhalVpNVPehGyvsWY10g==\r\n"	\
  "-----END CERTIFICATE-----\r\n"
/* END FILE */

/* This is generated from tests/data_files/server5.crt.der using `xxd -i`. */
/* BEGIN FILE binary macro TEST_SRV_CRT_EC_DER tests/data_files/server5.crt.der */
#define TEST_SRV_CRT_EC_DER {                                                \
    0x30, 0x82, 0x02, 0x1f, 0x30, 0x82, 0x01, 0xa5, 0xa0, 0x03, 0x02, 0x01,  \
    0x02, 0x02, 0x01, 0x09, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,  \
    0x3d, 0x04, 0x03, 0x02, 0x30, 0x3e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,  \
    0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, 0x30, 0x0f, 0x06,  \
    0x03, 0x55, 0x04, 0x0a, 0x13, 0x08, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53,  \
    0x53, 0x4c, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,  \
    0x13, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x73, 0x73, 0x6c, 0x20, 0x54, 0x65,  \
    0x73, 0x74, 0x20, 0x45, 0x43, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d,  \
    0x31, 0x33, 0x30, 0x39, 0x32, 0x34, 0x31, 0x35, 0x35, 0x32, 0x30, 0x34,  \
    0x5a, 0x17, 0x0d, 0x32, 0x33, 0x30, 0x39, 0x32, 0x32, 0x31, 0x35, 0x35,  \
    0x32, 0x30, 0x34, 0x5a, 0x30, 0x34, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,  \
    0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, 0x30, 0x0f, 0x06,  \
    0x03, 0x55, 0x04, 0x0a, 0x13, 0x08, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53,  \
    0x53, 0x4c, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,  \
    0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x59,  \
    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,  \
    0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,  \
    0x04, 0x37, 0xcc, 0x56, 0xd9, 0x76, 0x09, 0x1e, 0x5a, 0x72, 0x3e, 0xc7,  \
    0x59, 0x2d, 0xff, 0x20, 0x6e, 0xee, 0x7c, 0xf9, 0x06, 0x91, 0x74, 0xd0,  \
    0xad, 0x14, 0xb5, 0xf7, 0x68, 0x22, 0x59, 0x62, 0x92, 0x4e, 0xe5, 0x00,  \
    0xd8, 0x23, 0x11, 0xff, 0xea, 0x2f, 0xd2, 0x34, 0x5d, 0x5d, 0x16, 0xbd,  \
    0x8a, 0x88, 0xc2, 0x6b, 0x77, 0x0d, 0x55, 0xcd, 0x8a, 0x2a, 0x0e, 0xfa,  \
    0x01, 0xc8, 0xb4, 0xed, 0xff, 0xa3, 0x81, 0x9d, 0x30, 0x81, 0x9a, 0x30,  \
    0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x1d,  \
    0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x50, 0x61, 0xa5,  \
    0x8f, 0xd4, 0x07, 0xd9, 0xd7, 0x82, 0x01, 0x0c, 0xe5, 0x65, 0x7f, 0x8c,  \
    0x63, 0x46, 0xa7, 0x13, 0xbe, 0x30, 0x6e, 0x06, 0x03, 0x55, 0x1d, 0x23,  \
    0x04, 0x67, 0x30, 0x65, 0x80, 0x14, 0x9d, 0x6d, 0x20, 0x24, 0x49, 0x01,  \
    0x3f, 0x2b, 0xcb, 0x78, 0xb5, 0x19, 0xbc, 0x7e, 0x24, 0xc9, 0xdb, 0xfb,  \
    0x36, 0x7c, 0xa1, 0x42, 0xa4, 0x40, 0x30, 0x3e, 0x31, 0x0b, 0x30, 0x09,  \
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, 0x30,  \
    0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x08, 0x50, 0x6f, 0x6c, 0x61,  \
    0x72, 0x53, 0x53, 0x4c, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04,  \
    0x03, 0x13, 0x13, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x73, 0x73, 0x6c, 0x20,  \
    0x54, 0x65, 0x73, 0x74, 0x20, 0x45, 0x43, 0x20, 0x43, 0x41, 0x82, 0x09,  \
    0x00, 0xc1, 0x43, 0xe2, 0x7e, 0x62, 0x43, 0xcc, 0xe8, 0x30, 0x0a, 0x06,  \
    0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x68, 0x00,  \
    0x30, 0x65, 0x02, 0x31, 0x00, 0x9a, 0x2c, 0x5c, 0xd7, 0xa6, 0xdb, 0xa2,  \
    0xe5, 0x64, 0x0d, 0xf0, 0xb9, 0x4e, 0xdd, 0xd7, 0x61, 0xd6, 0x13, 0x31,  \
    0xc7, 0xab, 0x73, 0x80, 0xbb, 0xd3, 0xd3, 0x73, 0x13, 0x54, 0xad, 0x92,  \
    0x0b, 0x5d, 0xab, 0xd0, 0xbc, 0xf7, 0xae, 0x2f, 0xe6, 0xa1, 0x21, 0x29,  \
    0x35, 0x95, 0xaa, 0x3e, 0x39, 0x02, 0x30, 0x21, 0x36, 0x7f, 0x9d, 0xc6,  \
    0x5d, 0xc6, 0x0b, 0xab, 0x27, 0xf2, 0x25, 0x1d, 0x3b, 0xf1, 0xcf, 0xf1,  \
    0x35, 0x25, 0x14, 0xe7, 0xe5, 0xf1, 0x97, 0xb5, 0x59, 0xe3, 0x5e, 0x15,  \
    0x7c, 0x66, 0xb9, 0x90, 0x7b, 0xc7, 0x01, 0x10, 0x4f, 0x73, 0xc6, 0x00,  \
    0x21, 0x52, 0x2a, 0x0e, 0xf1, 0xc7, 0xd5                                 \
}
/* END FILE */

/* This is taken from tests/data_files/server5.key. */
/* BEGIN FILE string macro TEST_SRV_KEY_EC_PEM tests/data_files/server5.key */
#define TEST_SRV_KEY_EC_PEM                                                \
  "-----BEGIN EC PRIVATE KEY-----\r\n"	\
  "MIHcAgEBBEIARL2NqmjtQSNwf0wvYtQveTsnWzTORKmnYbbkvbSXBNtWuvrXHV0F\r\n"	\
  "bupM+y11nJA/9F9yUSmmn+Tqr7bisaiLw3ygBwYFK4EEACOhgYkDgYYABAAUINv1\r\n"	\
  "t0sceo02BkY9lxGfVsilbQiEA9eoseMLEnp4qJukF8Yb0uJ4A/Ioj6if+OQI1Yhe\r\n"	\
  "+TMeLwzbPDMDNEgcywE7M6oka/mmTYv84KogodwPOHJxKWKPqlONIl/wpHiokNkK\r\n"	\
  "c6zY1nx5ts1zDbmRcixjrKlolcjFOSWlAxfTC9+Hxg==\r\n"	\
  "-----END EC PRIVATE KEY-----\r\n"
/* END FILE */

/* This is generated from tests/data_files/server5.key.der using `xxd -i`. */
/* BEGIN FILE binary macro TEST_SRV_KEY_EC_DER tests/data_files/server5.key.der */
#define TEST_SRV_KEY_EC_DER {                                                \
    0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0xf1, 0x2a, 0x13, 0x20, 0x76,  \
    0x02, 0x70, 0xa8, 0x3c, 0xbf, 0xfd, 0x53, 0xf6, 0x03, 0x1e, 0xf7, 0x6a,  \
    0x5d, 0x86, 0xc8, 0xa2, 0x04, 0xf2, 0xc3, 0x0c, 0xa9, 0xeb, 0xf5, 0x1f,  \
    0x0f, 0x0e, 0xa7, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,  \
    0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x37, 0xcc, 0x56,  \
    0xd9, 0x76, 0x09, 0x1e, 0x5a, 0x72, 0x3e, 0xc7, 0x59, 0x2d, 0xff, 0x20,  \
    0x6e, 0xee, 0x7c, 0xf9, 0x06, 0x91, 0x74, 0xd0, 0xad, 0x14, 0xb5, 0xf7,  \
    0x68, 0x22, 0x59, 0x62, 0x92, 0x4e, 0xe5, 0x00, 0xd8, 0x23, 0x11, 0xff,  \
    0xea, 0x2f, 0xd2, 0x34, 0x5d, 0x5d, 0x16, 0xbd, 0x8a, 0x88, 0xc2, 0x6b,  \
    0x77, 0x0d, 0x55, 0xcd, 0x8a, 0x2a, 0x0e, 0xfa, 0x01, 0xc8, 0xb4, 0xed,  \
    0xff                                                                     \
}
/* END FILE */

/* This is taken from tests/data_files/server2-sha256.crt. */
/* BEGIN FILE string macro TEST_SRV_CRT_RSA_SHA256_PEM tests/data_files/server2-sha256.crt */
#define TEST_SRV_CRT_RSA_SHA256_PEM                                        \
    "-----BEGIN CERTIFICATE-----\r\n"                                      \
    "MIIDNzCCAh+gAwIBAgIBAjANBgkqhkiG9w0BAQsFADA7MQswCQYDVQQGEwJOTDER\r\n" \
    "MA8GA1UECgwIUG9sYXJTU0wxGTAXBgNVBAMMEFBvbGFyU1NMIFRlc3QgQ0EwHhcN\r\n" \
    "MTkwMjEwMTQ0NDA2WhcNMjkwMjEwMTQ0NDA2WjA0MQswCQYDVQQGEwJOTDERMA8G\r\n" \
    "A1UECgwIUG9sYXJTU0wxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcN\r\n" \
    "AQEBBQADggEPADCCAQoCggEBAMFNo93nzR3RBNdJcriZrA545Do8Ss86ExbQWuTN\r\n" \
    "owCIp+4ea5anUrSQ7y1yej4kmvy2NKwk9XfgJmSMnLAofaHa6ozmyRyWvP7BBFKz\r\n" \
    "NtSj+uGxdtiQwWG0ZlI2oiZTqqt0Xgd9GYLbKtgfoNkNHC1JZvdbJXNG6AuKT2kM\r\n" \
    "tQCQ4dqCEGZ9rlQri2V5kaHiYcPNQEkI7mgM8YuG0ka/0LiqEQMef1aoGh5EGA8P\r\n" \
    "hYvai0Re4hjGYi/HZo36Xdh98yeJKQHFkA4/J/EwyEoO79bex8cna8cFPXrEAjya\r\n" \
    "HT4P6DSYW8tzS1KW2BGiLICIaTla0w+w3lkvEcf36hIBMJcCAwEAAaNNMEswCQYD\r\n" \
    "VR0TBAIwADAdBgNVHQ4EFgQUpQXoZLjc32APUBJNYKhkr02LQ5MwHwYDVR0jBBgw\r\n" \
    "FoAUtFrkpbPe0lL2udWmlQ/rPrzH/f8wDQYJKoZIhvcNAQELBQADggEBAC465FJh\r\n" \
    "Pqel7zJngHIHJrqj/wVAxGAFOTF396XKATGAp+HRCqJ81Ry60CNK1jDzk8dv6M6U\r\n" \
    "HoS7RIFiM/9rXQCbJfiPD5xMTejZp5n5UYHAmxsxDaazfA5FuBhkfokKK6jD4Eq9\r\n" \
    "1C94xGKb6X4/VkaPF7cqoBBw/bHxawXc0UEPjqayiBpCYU/rJoVZgLqFVP7Px3sv\r\n" \
    "a1nOrNx8rPPI1hJ+ZOg8maiPTxHZnBVLakSSLQy/sWeWyazO1RnrbxjrbgQtYKz0\r\n" \
    "e3nwGpu1w13vfckFmUSBhHXH7AAS/HpKC4IH7G2GAk3+n8iSSN71sZzpxonQwVbo\r\n" \
    "pMZqLmbBm/7WPLc=\r\n"                                                 \
    "-----END CERTIFICATE-----\r\n"
/* END FILE */

/* This is taken from tests/data_files/server2-sha256.crt.der. */
/* BEGIN FILE binary macro TEST_SRV_CRT_RSA_SHA256_DER tests/data_files/server2-sha256.crt.der */
#define TEST_SRV_CRT_RSA_SHA256_DER {                                        \
  0x30, 0x82, 0x03, 0x37, 0x30, 0x82, 0x02, 0x1f, 0xa0, 0x03, 0x02, 0x01,    \
  0x02, 0x02, 0x01, 0x02, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,    \
  0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x3b, 0x31, 0x0b, 0x30,    \
  0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11,    \
  0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c,    \
  0x61, 0x72, 0x53, 0x53, 0x4c, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55,    \
  0x04, 0x03, 0x0c, 0x10, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c,    \
  0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d,    \
  0x31, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34, 0x34, 0x30, 0x36,    \
  0x5a, 0x17, 0x0d, 0x32, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34,    \
  0x34, 0x30, 0x36, 0x5a, 0x30, 0x34, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,    \
  0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, 0x30, 0x0f, 0x06,    \
  0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53,    \
  0x53, 0x4c, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,    \
  0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x82,    \
  0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,    \
  0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82,    \
  0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xc1, 0x4d, 0xa3, 0xdd, 0xe7,    \
  0xcd, 0x1d, 0xd1, 0x04, 0xd7, 0x49, 0x72, 0xb8, 0x99, 0xac, 0x0e, 0x78,    \
  0xe4, 0x3a, 0x3c, 0x4a, 0xcf, 0x3a, 0x13, 0x16, 0xd0, 0x5a, 0xe4, 0xcd,    \
  0xa3, 0x00, 0x88, 0xa7, 0xee, 0x1e, 0x6b, 0x96, 0xa7, 0x52, 0xb4, 0x90,    \
  0xef, 0x2d, 0x72, 0x7a, 0x3e, 0x24, 0x9a, 0xfc, 0xb6, 0x34, 0xac, 0x24,    \
  0xf5, 0x77, 0xe0, 0x26, 0x64, 0x8c, 0x9c, 0xb0, 0x28, 0x7d, 0xa1, 0xda,    \
  0xea, 0x8c, 0xe6, 0xc9, 0x1c, 0x96, 0xbc, 0xfe, 0xc1, 0x04, 0x52, 0xb3,    \
  0x36, 0xd4, 0xa3, 0xfa, 0xe1, 0xb1, 0x76, 0xd8, 0x90, 0xc1, 0x61, 0xb4,    \
  0x66, 0x52, 0x36, 0xa2, 0x26, 0x53, 0xaa, 0xab, 0x74, 0x5e, 0x07, 0x7d,    \
  0x19, 0x82, 0xdb, 0x2a, 0xd8, 0x1f, 0xa0, 0xd9, 0x0d, 0x1c, 0x2d, 0x49,    \
  0x66, 0xf7, 0x5b, 0x25, 0x73, 0x46, 0xe8, 0x0b, 0x8a, 0x4f, 0x69, 0x0c,    \
  0xb5, 0x00, 0x90, 0xe1, 0xda, 0x82, 0x10, 0x66, 0x7d, 0xae, 0x54, 0x2b,    \
  0x8b, 0x65, 0x79, 0x91, 0xa1, 0xe2, 0x61, 0xc3, 0xcd, 0x40, 0x49, 0x08,    \
  0xee, 0x68, 0x0c, 0xf1, 0x8b, 0x86, 0xd2, 0x46, 0xbf, 0xd0, 0xb8, 0xaa,    \
  0x11, 0x03, 0x1e, 0x7f, 0x56, 0xa8, 0x1a, 0x1e, 0x44, 0x18, 0x0f, 0x0f,    \
  0x85, 0x8b, 0xda, 0x8b, 0x44, 0x5e, 0xe2, 0x18, 0xc6, 0x62, 0x2f, 0xc7,    \
  0x66, 0x8d, 0xfa, 0x5d, 0xd8, 0x7d, 0xf3, 0x27, 0x89, 0x29, 0x01, 0xc5,    \
  0x90, 0x0e, 0x3f, 0x27, 0xf1, 0x30, 0xc8, 0x4a, 0x0e, 0xef, 0xd6, 0xde,    \
  0xc7, 0xc7, 0x27, 0x6b, 0xc7, 0x05, 0x3d, 0x7a, 0xc4, 0x02, 0x3c, 0x9a,    \
  0x1d, 0x3e, 0x0f, 0xe8, 0x34, 0x98, 0x5b, 0xcb, 0x73, 0x4b, 0x52, 0x96,    \
  0xd8, 0x11, 0xa2, 0x2c, 0x80, 0x88, 0x69, 0x39, 0x5a, 0xd3, 0x0f, 0xb0,    \
  0xde, 0x59, 0x2f, 0x11, 0xc7, 0xf7, 0xea, 0x12, 0x01, 0x30, 0x97, 0x02,    \
  0x03, 0x01, 0x00, 0x01, 0xa3, 0x4d, 0x30, 0x4b, 0x30, 0x09, 0x06, 0x03,    \
  0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x1d, 0x06, 0x03, 0x55,    \
  0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xa5, 0x05, 0xe8, 0x64, 0xb8, 0xdc,    \
  0xdf, 0x60, 0x0f, 0x50, 0x12, 0x4d, 0x60, 0xa8, 0x64, 0xaf, 0x4d, 0x8b,    \
  0x43, 0x93, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30,    \
  0x16, 0x80, 0x14, 0xb4, 0x5a, 0xe4, 0xa5, 0xb3, 0xde, 0xd2, 0x52, 0xf6,    \
  0xb9, 0xd5, 0xa6, 0x95, 0x0f, 0xeb, 0x3e, 0xbc, 0xc7, 0xfd, 0xff, 0x30,    \
  0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,    \
  0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x2e, 0x3a, 0xe4, 0x52, 0x61,    \
  0x3e, 0xa7, 0xa5, 0xef, 0x32, 0x67, 0x80, 0x72, 0x07, 0x26, 0xba, 0xa3,    \
  0xff, 0x05, 0x40, 0xc4, 0x60, 0x05, 0x39, 0x31, 0x77, 0xf7, 0xa5, 0xca,    \
  0x01, 0x31, 0x80, 0xa7, 0xe1, 0xd1, 0x0a, 0xa2, 0x7c, 0xd5, 0x1c, 0xba,    \
  0xd0, 0x23, 0x4a, 0xd6, 0x30, 0xf3, 0x93, 0xc7, 0x6f, 0xe8, 0xce, 0x94,    \
  0x1e, 0x84, 0xbb, 0x44, 0x81, 0x62, 0x33, 0xff, 0x6b, 0x5d, 0x00, 0x9b,    \
  0x25, 0xf8, 0x8f, 0x0f, 0x9c, 0x4c, 0x4d, 0xe8, 0xd9, 0xa7, 0x99, 0xf9,    \
  0x51, 0x81, 0xc0, 0x9b, 0x1b, 0x31, 0x0d, 0xa6, 0xb3, 0x7c, 0x0e, 0x45,    \
  0xb8, 0x18, 0x64, 0x7e, 0x89, 0x0a, 0x2b, 0xa8, 0xc3, 0xe0, 0x4a, 0xbd,    \
  0xd4, 0x2f, 0x78, 0xc4, 0x62, 0x9b, 0xe9, 0x7e, 0x3f, 0x56, 0x46, 0x8f,    \
  0x17, 0xb7, 0x2a, 0xa0, 0x10, 0x70, 0xfd, 0xb1, 0xf1, 0x6b, 0x05, 0xdc,    \
  0xd1, 0x41, 0x0f, 0x8e, 0xa6, 0xb2, 0x88, 0x1a, 0x42, 0x61, 0x4f, 0xeb,    \
  0x26, 0x85, 0x59, 0x80, 0xba, 0x85, 0x54, 0xfe, 0xcf, 0xc7, 0x7b, 0x2f,    \
  0x6b, 0x59, 0xce, 0xac, 0xdc, 0x7c, 0xac, 0xf3, 0xc8, 0xd6, 0x12, 0x7e,    \
  0x64, 0xe8, 0x3c, 0x99, 0xa8, 0x8f, 0x4f, 0x11, 0xd9, 0x9c, 0x15, 0x4b,    \
  0x6a, 0x44, 0x92, 0x2d, 0x0c, 0xbf, 0xb1, 0x67, 0x96, 0xc9, 0xac, 0xce,    \
  0xd5, 0x19, 0xeb, 0x6f, 0x18, 0xeb, 0x6e, 0x04, 0x2d, 0x60, 0xac, 0xf4,    \
  0x7b, 0x79, 0xf0, 0x1a, 0x9b, 0xb5, 0xc3, 0x5d, 0xef, 0x7d, 0xc9, 0x05,    \
  0x99, 0x44, 0x81, 0x84, 0x75, 0xc7, 0xec, 0x00, 0x12, 0xfc, 0x7a, 0x4a,    \
  0x0b, 0x82, 0x07, 0xec, 0x6d, 0x86, 0x02, 0x4d, 0xfe, 0x9f, 0xc8, 0x92,    \
  0x48, 0xde, 0xf5, 0xb1, 0x9c, 0xe9, 0xc6, 0x89, 0xd0, 0xc1, 0x56, 0xe8,    \
  0xa4, 0xc6, 0x6a, 0x2e, 0x66, 0xc1, 0x9b, 0xfe, 0xd6, 0x3c, 0xb7           \
}
/* END FILE */

/* This is taken from tests/data_files/server2.crt. */
/* BEGIN FILE string macro TEST_SRV_CRT_RSA_SHA1_PEM tests/data_files/server2.crt */
#define TEST_SRV_CRT_RSA_SHA1_PEM                                          \
    "-----BEGIN CERTIFICATE-----\r\n"                                      \
    "MIIDNzCCAh+gAwIBAgIBAjANBgkqhkiG9w0BAQUFADA7MQswCQYDVQQGEwJOTDER\r\n" \
    "MA8GA1UECgwIUG9sYXJTU0wxGTAXBgNVBAMMEFBvbGFyU1NMIFRlc3QgQ0EwHhcN\r\n" \
    "MTkwMjEwMTQ0NDA2WhcNMjkwMjEwMTQ0NDA2WjA0MQswCQYDVQQGEwJOTDERMA8G\r\n" \
    "A1UECgwIUG9sYXJTU0wxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcN\r\n" \
    "AQEBBQADggEPADCCAQoCggEBAMFNo93nzR3RBNdJcriZrA545Do8Ss86ExbQWuTN\r\n" \
    "owCIp+4ea5anUrSQ7y1yej4kmvy2NKwk9XfgJmSMnLAofaHa6ozmyRyWvP7BBFKz\r\n" \
    "NtSj+uGxdtiQwWG0ZlI2oiZTqqt0Xgd9GYLbKtgfoNkNHC1JZvdbJXNG6AuKT2kM\r\n" \
    "tQCQ4dqCEGZ9rlQri2V5kaHiYcPNQEkI7mgM8YuG0ka/0LiqEQMef1aoGh5EGA8P\r\n" \
    "hYvai0Re4hjGYi/HZo36Xdh98yeJKQHFkA4/J/EwyEoO79bex8cna8cFPXrEAjya\r\n" \
    "HT4P6DSYW8tzS1KW2BGiLICIaTla0w+w3lkvEcf36hIBMJcCAwEAAaNNMEswCQYD\r\n" \
    "VR0TBAIwADAdBgNVHQ4EFgQUpQXoZLjc32APUBJNYKhkr02LQ5MwHwYDVR0jBBgw\r\n" \
    "FoAUtFrkpbPe0lL2udWmlQ/rPrzH/f8wDQYJKoZIhvcNAQEFBQADggEBAJklg3Q4\r\n" \
    "cB7v7BzsxM/vLyKccO6op0/gZzM4ghuLq2Y32kl0sM6kSNUUmduuq3u/+GmUZN2A\r\n" \
    "O/7c+Hw7hDFEIvZk98aBGjCLqn3DmgHIv8ToQ67nellQxx2Uj309PdgjNi/r9HOc\r\n" \
    "KNAYPbBcg6MJGWWj2TI6vNaceios/DhOYx5V0j5nfqSJ/pnU0g9Ign2LAhgYpGJE\r\n" \
    "iEM9wW7hEMkwmk0h/sqZsrJsGH5YsF/VThSq/JVO1e2mZH2vruyZKJVBq+8tDNYp\r\n" \
    "HkK6tSyVYQhzIt3StMJWKMl/o5k2AYz6tSC164+1oG+ML3LWg8XrGKa91H4UOKap\r\n" \
    "Awgk0+4m0T25cNs=\r\n"                                                 \
    "-----END CERTIFICATE-----\r\n"
/* END FILE */

/* This is taken from tests/data_files/server2.crt.der. */
/* BEGIN FILE binary macro TEST_SRV_CRT_RSA_SHA1_DER tests/data_files/server2.crt.der */
#define TEST_SRV_CRT_RSA_SHA1_DER {                                          \
  0x30, 0x82, 0x03, 0x37, 0x30, 0x82, 0x02, 0x1f, 0xa0, 0x03, 0x02, 0x01,    \
  0x02, 0x02, 0x01, 0x02, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,    \
  0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x3b, 0x31, 0x0b, 0x30,    \
  0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11,    \
  0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c,    \
  0x61, 0x72, 0x53, 0x53, 0x4c, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55,    \
  0x04, 0x03, 0x0c, 0x10, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c,    \
  0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d,    \
  0x31, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34, 0x34, 0x30, 0x36,    \
  0x5a, 0x17, 0x0d, 0x32, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34,    \
  0x34, 0x30, 0x36, 0x5a, 0x30, 0x34, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,    \
  0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, 0x30, 0x0f, 0x06,    \
  0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53,    \
  0x53, 0x4c, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,    \
  0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x82,    \
  0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,    \
  0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82,    \
  0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xc1, 0x4d, 0xa3, 0xdd, 0xe7,    \
  0xcd, 0x1d, 0xd1, 0x04, 0xd7, 0x49, 0x72, 0xb8, 0x99, 0xac, 0x0e, 0x78,    \
  0xe4, 0x3a, 0x3c, 0x4a, 0xcf, 0x3a, 0x13, 0x16, 0xd0, 0x5a, 0xe4, 0xcd,    \
  0xa3, 0x00, 0x88, 0xa7, 0xee, 0x1e, 0x6b, 0x96, 0xa7, 0x52, 0xb4, 0x90,    \
  0xef, 0x2d, 0x72, 0x7a, 0x3e, 0x24, 0x9a, 0xfc, 0xb6, 0x34, 0xac, 0x24,    \
  0xf5, 0x77, 0xe0, 0x26, 0x64, 0x8c, 0x9c, 0xb0, 0x28, 0x7d, 0xa1, 0xda,    \
  0xea, 0x8c, 0xe6, 0xc9, 0x1c, 0x96, 0xbc, 0xfe, 0xc1, 0x04, 0x52, 0xb3,    \
  0x36, 0xd4, 0xa3, 0xfa, 0xe1, 0xb1, 0x76, 0xd8, 0x90, 0xc1, 0x61, 0xb4,    \
  0x66, 0x52, 0x36, 0xa2, 0x26, 0x53, 0xaa, 0xab, 0x74, 0x5e, 0x07, 0x7d,    \
  0x19, 0x82, 0xdb, 0x2a, 0xd8, 0x1f, 0xa0, 0xd9, 0x0d, 0x1c, 0x2d, 0x49,    \
  0x66, 0xf7, 0x5b, 0x25, 0x73, 0x46, 0xe8, 0x0b, 0x8a, 0x4f, 0x69, 0x0c,    \
  0xb5, 0x00, 0x90, 0xe1, 0xda, 0x82, 0x10, 0x66, 0x7d, 0xae, 0x54, 0x2b,    \
  0x8b, 0x65, 0x79, 0x91, 0xa1, 0xe2, 0x61, 0xc3, 0xcd, 0x40, 0x49, 0x08,    \
  0xee, 0x68, 0x0c, 0xf1, 0x8b, 0x86, 0xd2, 0x46, 0xbf, 0xd0, 0xb8, 0xaa,    \
  0x11, 0x03, 0x1e, 0x7f, 0x56, 0xa8, 0x1a, 0x1e, 0x44, 0x18, 0x0f, 0x0f,    \
  0x85, 0x8b, 0xda, 0x8b, 0x44, 0x5e, 0xe2, 0x18, 0xc6, 0x62, 0x2f, 0xc7,    \
  0x66, 0x8d, 0xfa, 0x5d, 0xd8, 0x7d, 0xf3, 0x27, 0x89, 0x29, 0x01, 0xc5,    \
  0x90, 0x0e, 0x3f, 0x27, 0xf1, 0x30, 0xc8, 0x4a, 0x0e, 0xef, 0xd6, 0xde,    \
  0xc7, 0xc7, 0x27, 0x6b, 0xc7, 0x05, 0x3d, 0x7a, 0xc4, 0x02, 0x3c, 0x9a,    \
  0x1d, 0x3e, 0x0f, 0xe8, 0x34, 0x98, 0x5b, 0xcb, 0x73, 0x4b, 0x52, 0x96,    \
  0xd8, 0x11, 0xa2, 0x2c, 0x80, 0x88, 0x69, 0x39, 0x5a, 0xd3, 0x0f, 0xb0,    \
  0xde, 0x59, 0x2f, 0x11, 0xc7, 0xf7, 0xea, 0x12, 0x01, 0x30, 0x97, 0x02,    \
  0x03, 0x01, 0x00, 0x01, 0xa3, 0x4d, 0x30, 0x4b, 0x30, 0x09, 0x06, 0x03,    \
  0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x1d, 0x06, 0x03, 0x55,    \
  0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xa5, 0x05, 0xe8, 0x64, 0xb8, 0xdc,    \
  0xdf, 0x60, 0x0f, 0x50, 0x12, 0x4d, 0x60, 0xa8, 0x64, 0xaf, 0x4d, 0x8b,    \
  0x43, 0x93, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30,    \
  0x16, 0x80, 0x14, 0xb4, 0x5a, 0xe4, 0xa5, 0xb3, 0xde, 0xd2, 0x52, 0xf6,    \
  0xb9, 0xd5, 0xa6, 0x95, 0x0f, 0xeb, 0x3e, 0xbc, 0xc7, 0xfd, 0xff, 0x30,    \
  0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05,    \
  0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x99, 0x25, 0x83, 0x74, 0x38,    \
  0x70, 0x1e, 0xef, 0xec, 0x1c, 0xec, 0xc4, 0xcf, 0xef, 0x2f, 0x22, 0x9c,    \
  0x70, 0xee, 0xa8, 0xa7, 0x4f, 0xe0, 0x67, 0x33, 0x38, 0x82, 0x1b, 0x8b,    \
  0xab, 0x66, 0x37, 0xda, 0x49, 0x74, 0xb0, 0xce, 0xa4, 0x48, 0xd5, 0x14,    \
  0x99, 0xdb, 0xae, 0xab, 0x7b, 0xbf, 0xf8, 0x69, 0x94, 0x64, 0xdd, 0x80,    \
  0x3b, 0xfe, 0xdc, 0xf8, 0x7c, 0x3b, 0x84, 0x31, 0x44, 0x22, 0xf6, 0x64,    \
  0xf7, 0xc6, 0x81, 0x1a, 0x30, 0x8b, 0xaa, 0x7d, 0xc3, 0x9a, 0x01, 0xc8,    \
  0xbf, 0xc4, 0xe8, 0x43, 0xae, 0xe7, 0x7a, 0x59, 0x50, 0xc7, 0x1d, 0x94,    \
  0x8f, 0x7d, 0x3d, 0x3d, 0xd8, 0x23, 0x36, 0x2f, 0xeb, 0xf4, 0x73, 0x9c,    \
  0x28, 0xd0, 0x18, 0x3d, 0xb0, 0x5c, 0x83, 0xa3, 0x09, 0x19, 0x65, 0xa3,    \
  0xd9, 0x32, 0x3a, 0xbc, 0xd6, 0x9c, 0x7a, 0x2a, 0x2c, 0xfc, 0x38, 0x4e,    \
  0x63, 0x1e, 0x55, 0xd2, 0x3e, 0x67, 0x7e, 0xa4, 0x89, 0xfe, 0x99, 0xd4,    \
  0xd2, 0x0f, 0x48, 0x82, 0x7d, 0x8b, 0x02, 0x18, 0x18, 0xa4, 0x62, 0x44,    \
  0x88, 0x43, 0x3d, 0xc1, 0x6e, 0xe1, 0x10, 0xc9, 0x30, 0x9a, 0x4d, 0x21,    \
  0xfe, 0xca, 0x99, 0xb2, 0xb2, 0x6c, 0x18, 0x7e, 0x58, 0xb0, 0x5f, 0xd5,    \
  0x4e, 0x14, 0xaa, 0xfc, 0x95, 0x4e, 0xd5, 0xed, 0xa6, 0x64, 0x7d, 0xaf,    \
  0xae, 0xec, 0x99, 0x28, 0x95, 0x41, 0xab, 0xef, 0x2d, 0x0c, 0xd6, 0x29,    \
  0x1e, 0x42, 0xba, 0xb5, 0x2c, 0x95, 0x61, 0x08, 0x73, 0x22, 0xdd, 0xd2,    \
  0xb4, 0xc2, 0x56, 0x28, 0xc9, 0x7f, 0xa3, 0x99, 0x36, 0x01, 0x8c, 0xfa,    \
  0xb5, 0x20, 0xb5, 0xeb, 0x8f, 0xb5, 0xa0, 0x6f, 0x8c, 0x2f, 0x72, 0xd6,    \
  0x83, 0xc5, 0xeb, 0x18, 0xa6, 0xbd, 0xd4, 0x7e, 0x14, 0x38, 0xa6, 0xa9,    \
  0x03, 0x08, 0x24, 0xd3, 0xee, 0x26, 0xd1, 0x3d, 0xb9, 0x70, 0xdb           \
}
/* END FILE */

/* This is taken from tests/data_files/server2.key. */
/* BEGIN FILE string macro TEST_SRV_KEY_RSA_PEM tests/data_files/server2.key */
#define TEST_SRV_KEY_RSA_PEM                                               \
    "-----BEGIN RSA PRIVATE KEY-----\r\n"                                  \
    "MIIEpAIBAAKCAQEAwU2j3efNHdEE10lyuJmsDnjkOjxKzzoTFtBa5M2jAIin7h5r\r\n" \
    "lqdStJDvLXJ6PiSa/LY0rCT1d+AmZIycsCh9odrqjObJHJa8/sEEUrM21KP64bF2\r\n" \
    "2JDBYbRmUjaiJlOqq3ReB30Zgtsq2B+g2Q0cLUlm91slc0boC4pPaQy1AJDh2oIQ\r\n" \
    "Zn2uVCuLZXmRoeJhw81ASQjuaAzxi4bSRr/QuKoRAx5/VqgaHkQYDw+Fi9qLRF7i\r\n" \
    "GMZiL8dmjfpd2H3zJ4kpAcWQDj8n8TDISg7v1t7HxydrxwU9esQCPJodPg/oNJhb\r\n" \
    "y3NLUpbYEaIsgIhpOVrTD7DeWS8Rx/fqEgEwlwIDAQABAoIBAQCXR0S8EIHFGORZ\r\n" \
    "++AtOg6eENxD+xVs0f1IeGz57Tjo3QnXX7VBZNdj+p1ECvhCE/G7XnkgU5hLZX+G\r\n" \
    "Z0jkz/tqJOI0vRSdLBbipHnWouyBQ4e/A1yIJdlBtqXxJ1KE/ituHRbNc4j4kL8Z\r\n" \
    "/r6pvwnTI0PSx2Eqs048YdS92LT6qAv4flbNDxMn2uY7s4ycS4Q8w1JXnCeaAnYm\r\n" \
    "WYI5wxO+bvRELR2Mcz5DmVnL8jRyml6l6582bSv5oufReFIbyPZbQWlXgYnpu6He\r\n" \
    "GTc7E1zKYQGG/9+DQUl/1vQuCPqQwny0tQoX2w5tdYpdMdVm+zkLtbajzdTviJJa\r\n" \
    "TWzL6lt5AoGBAN86+SVeJDcmQJcv4Eq6UhtRr4QGMiQMz0Sod6ettYxYzMgxtw28\r\n" \
    "CIrgpozCc+UaZJLo7UxvC6an85r1b2nKPCLQFaggJ0H4Q0J/sZOhBIXaoBzWxveK\r\n" \
    "nupceKdVxGsFi8CDy86DBfiyFivfBj+47BbaQzPBj7C4rK7UlLjab2rDAoGBAN2u\r\n" \
    "AM2gchoFiu4v1HFL8D7lweEpi6ZnMJjnEu/dEgGQJFjwdpLnPbsj4c75odQ4Gz8g\r\n" \
    "sw9lao9VVzbusoRE/JGI4aTdO0pATXyG7eG1Qu+5Yc1YGXcCrliA2xM9xx+d7f+s\r\n" \
    "mPzN+WIEg5GJDYZDjAzHG5BNvi/FfM1C9dOtjv2dAoGAF0t5KmwbjWHBhcVqO4Ic\r\n" \
    "BVvN3BIlc1ue2YRXEDlxY5b0r8N4XceMgKmW18OHApZxfl8uPDauWZLXOgl4uepv\r\n" \
    "whZC3EuWrSyyICNhLY21Ah7hbIEBPF3L3ZsOwC+UErL+dXWLdB56Jgy3gZaBeW7b\r\n" \
    "vDrEnocJbqCm7IukhXHOBK8CgYEAwqdHB0hqyNSzIOGY7v9abzB6pUdA3BZiQvEs\r\n" \
    "3LjHVd4HPJ2x0N8CgrBIWOE0q8+0hSMmeE96WW/7jD3fPWwCR5zlXknxBQsfv0gP\r\n" \
    "3BC5PR0Qdypz+d+9zfMf625kyit4T/hzwhDveZUzHnk1Cf+IG7Q+TOEnLnWAWBED\r\n" \
    "ISOWmrUCgYAFEmRxgwAc/u+D6t0syCwAYh6POtscq9Y0i9GyWk89NzgC4NdwwbBH\r\n" \
    "4AgahOxIxXx2gxJnq3yfkJfIjwf0s2DyP0kY2y6Ua1OeomPeY9mrIS4tCuDQ6LrE\r\n" \
    "TB6l9VGoxJL4fyHnZb8L5gGvnB1bbD8cL6YPaDiOhcRseC9vBiEuVg==\r\n"         \
    "-----END RSA PRIVATE KEY-----\r\n"
/* END FILE */

/* This was generated from tests/data_files/server2.key.der using `xxd -i`. */
/* BEGIN FILE binary macro TEST_SRV_KEY_RSA_DER tests/data_files/server2.key.der */
#define TEST_SRV_KEY_RSA_DER {                                               \
    0x30, 0x82, 0x04, 0xa4, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,  \
    0xc1, 0x4d, 0xa3, 0xdd, 0xe7, 0xcd, 0x1d, 0xd1, 0x04, 0xd7, 0x49, 0x72,  \
    0xb8, 0x99, 0xac, 0x0e, 0x78, 0xe4, 0x3a, 0x3c, 0x4a, 0xcf, 0x3a, 0x13,  \
    0x16, 0xd0, 0x5a, 0xe4, 0xcd, 0xa3, 0x00, 0x88, 0xa7, 0xee, 0x1e, 0x6b,  \
    0x96, 0xa7, 0x52, 0xb4, 0x90, 0xef, 0x2d, 0x72, 0x7a, 0x3e, 0x24, 0x9a,  \
    0xfc, 0xb6, 0x34, 0xac, 0x24, 0xf5, 0x77, 0xe0, 0x26, 0x64, 0x8c, 0x9c,  \
    0xb0, 0x28, 0x7d, 0xa1, 0xda, 0xea, 0x8c, 0xe6, 0xc9, 0x1c, 0x96, 0xbc,  \
    0xfe, 0xc1, 0x04, 0x52, 0xb3, 0x36, 0xd4, 0xa3, 0xfa, 0xe1, 0xb1, 0x76,  \
    0xd8, 0x90, 0xc1, 0x61, 0xb4, 0x66, 0x52, 0x36, 0xa2, 0x26, 0x53, 0xaa,  \
    0xab, 0x74, 0x5e, 0x07, 0x7d, 0x19, 0x82, 0xdb, 0x2a, 0xd8, 0x1f, 0xa0,  \
    0xd9, 0x0d, 0x1c, 0x2d, 0x49, 0x66, 0xf7, 0x5b, 0x25, 0x73, 0x46, 0xe8,  \
    0x0b, 0x8a, 0x4f, 0x69, 0x0c, 0xb5, 0x00, 0x90, 0xe1, 0xda, 0x82, 0x10,  \
    0x66, 0x7d, 0xae, 0x54, 0x2b, 0x8b, 0x65, 0x79, 0x91, 0xa1, 0xe2, 0x61,  \
    0xc3, 0xcd, 0x40, 0x49, 0x08, 0xee, 0x68, 0x0c, 0xf1, 0x8b, 0x86, 0xd2,  \
    0x46, 0xbf, 0xd0, 0xb8, 0xaa, 0x11, 0x03, 0x1e, 0x7f, 0x56, 0xa8, 0x1a,  \
    0x1e, 0x44, 0x18, 0x0f, 0x0f, 0x85, 0x8b, 0xda, 0x8b, 0x44, 0x5e, 0xe2,  \
    0x18, 0xc6, 0x62, 0x2f, 0xc7, 0x66, 0x8d, 0xfa, 0x5d, 0xd8, 0x7d, 0xf3,  \
    0x27, 0x89, 0x29, 0x01, 0xc5, 0x90, 0x0e, 0x3f, 0x27, 0xf1, 0x30, 0xc8,  \
    0x4a, 0x0e, 0xef, 0xd6, 0xde, 0xc7, 0xc7, 0x27, 0x6b, 0xc7, 0x05, 0x3d,  \
    0x7a, 0xc4, 0x02, 0x3c, 0x9a, 0x1d, 0x3e, 0x0f, 0xe8, 0x34, 0x98, 0x5b,  \
    0xcb, 0x73, 0x4b, 0x52, 0x96, 0xd8, 0x11, 0xa2, 0x2c, 0x80, 0x88, 0x69,  \
    0x39, 0x5a, 0xd3, 0x0f, 0xb0, 0xde, 0x59, 0x2f, 0x11, 0xc7, 0xf7, 0xea,  \
    0x12, 0x01, 0x30, 0x97, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01,  \
    0x01, 0x00, 0x97, 0x47, 0x44, 0xbc, 0x10, 0x81, 0xc5, 0x18, 0xe4, 0x59,  \
    0xfb, 0xe0, 0x2d, 0x3a, 0x0e, 0x9e, 0x10, 0xdc, 0x43, 0xfb, 0x15, 0x6c,  \
    0xd1, 0xfd, 0x48, 0x78, 0x6c, 0xf9, 0xed, 0x38, 0xe8, 0xdd, 0x09, 0xd7,  \
    0x5f, 0xb5, 0x41, 0x64, 0xd7, 0x63, 0xfa, 0x9d, 0x44, 0x0a, 0xf8, 0x42,  \
    0x13, 0xf1, 0xbb, 0x5e, 0x79, 0x20, 0x53, 0x98, 0x4b, 0x65, 0x7f, 0x86,  \
    0x67, 0x48, 0xe4, 0xcf, 0xfb, 0x6a, 0x24, 0xe2, 0x34, 0xbd, 0x14, 0x9d,  \
    0x2c, 0x16, 0xe2, 0xa4, 0x79, 0xd6, 0xa2, 0xec, 0x81, 0x43, 0x87, 0xbf,  \
    0x03, 0x5c, 0x88, 0x25, 0xd9, 0x41, 0xb6, 0xa5, 0xf1, 0x27, 0x52, 0x84,  \
    0xfe, 0x2b, 0x6e, 0x1d, 0x16, 0xcd, 0x73, 0x88, 0xf8, 0x90, 0xbf, 0x19,  \
    0xfe, 0xbe, 0xa9, 0xbf, 0x09, 0xd3, 0x23, 0x43, 0xd2, 0xc7, 0x61, 0x2a,  \
    0xb3, 0x4e, 0x3c, 0x61, 0xd4, 0xbd, 0xd8, 0xb4, 0xfa, 0xa8, 0x0b, 0xf8,  \
    0x7e, 0x56, 0xcd, 0x0f, 0x13, 0x27, 0xda, 0xe6, 0x3b, 0xb3, 0x8c, 0x9c,  \
    0x4b, 0x84, 0x3c, 0xc3, 0x52, 0x57, 0x9c, 0x27, 0x9a, 0x02, 0x76, 0x26,  \
    0x59, 0x82, 0x39, 0xc3, 0x13, 0xbe, 0x6e, 0xf4, 0x44, 0x2d, 0x1d, 0x8c,  \
    0x73, 0x3e, 0x43, 0x99, 0x59, 0xcb, 0xf2, 0x34, 0x72, 0x9a, 0x5e, 0xa5,  \
    0xeb, 0x9f, 0x36, 0x6d, 0x2b, 0xf9, 0xa2, 0xe7, 0xd1, 0x78, 0x52, 0x1b,  \
    0xc8, 0xf6, 0x5b, 0x41, 0x69, 0x57, 0x81, 0x89, 0xe9, 0xbb, 0xa1, 0xde,  \
    0x19, 0x37, 0x3b, 0x13, 0x5c, 0xca, 0x61, 0x01, 0x86, 0xff, 0xdf, 0x83,  \
    0x41, 0x49, 0x7f, 0xd6, 0xf4, 0x2e, 0x08, 0xfa, 0x90, 0xc2, 0x7c, 0xb4,  \
    0xb5, 0x0a, 0x17, 0xdb, 0x0e, 0x6d, 0x75, 0x8a, 0x5d, 0x31, 0xd5, 0x66,  \
    0xfb, 0x39, 0x0b, 0xb5, 0xb6, 0xa3, 0xcd, 0xd4, 0xef, 0x88, 0x92, 0x5a,  \
    0x4d, 0x6c, 0xcb, 0xea, 0x5b, 0x79, 0x02, 0x81, 0x81, 0x00, 0xdf, 0x3a,  \
    0xf9, 0x25, 0x5e, 0x24, 0x37, 0x26, 0x40, 0x97, 0x2f, 0xe0, 0x4a, 0xba,  \
    0x52, 0x1b, 0x51, 0xaf, 0x84, 0x06, 0x32, 0x24, 0x0c, 0xcf, 0x44, 0xa8,  \
    0x77, 0xa7, 0xad, 0xb5, 0x8c, 0x58, 0xcc, 0xc8, 0x31, 0xb7, 0x0d, 0xbc,  \
    0x08, 0x8a, 0xe0, 0xa6, 0x8c, 0xc2, 0x73, 0xe5, 0x1a, 0x64, 0x92, 0xe8,  \
    0xed, 0x4c, 0x6f, 0x0b, 0xa6, 0xa7, 0xf3, 0x9a, 0xf5, 0x6f, 0x69, 0xca,  \
    0x3c, 0x22, 0xd0, 0x15, 0xa8, 0x20, 0x27, 0x41, 0xf8, 0x43, 0x42, 0x7f,  \
    0xb1, 0x93, 0xa1, 0x04, 0x85, 0xda, 0xa0, 0x1c, 0xd6, 0xc6, 0xf7, 0x8a,  \
    0x9e, 0xea, 0x5c, 0x78, 0xa7, 0x55, 0xc4, 0x6b, 0x05, 0x8b, 0xc0, 0x83,  \
    0xcb, 0xce, 0x83, 0x05, 0xf8, 0xb2, 0x16, 0x2b, 0xdf, 0x06, 0x3f, 0xb8,  \
    0xec, 0x16, 0xda, 0x43, 0x33, 0xc1, 0x8f, 0xb0, 0xb8, 0xac, 0xae, 0xd4,  \
    0x94, 0xb8, 0xda, 0x6f, 0x6a, 0xc3, 0x02, 0x81, 0x81, 0x00, 0xdd, 0xae,  \
    0x00, 0xcd, 0xa0, 0x72, 0x1a, 0x05, 0x8a, 0xee, 0x2f, 0xd4, 0x71, 0x4b,  \
    0xf0, 0x3e, 0xe5, 0xc1, 0xe1, 0x29, 0x8b, 0xa6, 0x67, 0x30, 0x98, 0xe7,  \
    0x12, 0xef, 0xdd, 0x12, 0x01, 0x90, 0x24, 0x58, 0xf0, 0x76, 0x92, 0xe7,  \
    0x3d, 0xbb, 0x23, 0xe1, 0xce, 0xf9, 0xa1, 0xd4, 0x38, 0x1b, 0x3f, 0x20,  \
    0xb3, 0x0f, 0x65, 0x6a, 0x8f, 0x55, 0x57, 0x36, 0xee, 0xb2, 0x84, 0x44,  \
    0xfc, 0x91, 0x88, 0xe1, 0xa4, 0xdd, 0x3b, 0x4a, 0x40, 0x4d, 0x7c, 0x86,  \
    0xed, 0xe1, 0xb5, 0x42, 0xef, 0xb9, 0x61, 0xcd, 0x58, 0x19, 0x77, 0x02,  \
    0xae, 0x58, 0x80, 0xdb, 0x13, 0x3d, 0xc7, 0x1f, 0x9d, 0xed, 0xff, 0xac,  \
    0x98, 0xfc, 0xcd, 0xf9, 0x62, 0x04, 0x83, 0x91, 0x89, 0x0d, 0x86, 0x43,  \
    0x8c, 0x0c, 0xc7, 0x1b, 0x90, 0x4d, 0xbe, 0x2f, 0xc5, 0x7c, 0xcd, 0x42,  \
    0xf5, 0xd3, 0xad, 0x8e, 0xfd, 0x9d, 0x02, 0x81, 0x80, 0x17, 0x4b, 0x79,  \
    0x2a, 0x6c, 0x1b, 0x8d, 0x61, 0xc1, 0x85, 0xc5, 0x6a, 0x3b, 0x82, 0x1c,  \
    0x05, 0x5b, 0xcd, 0xdc, 0x12, 0x25, 0x73, 0x5b, 0x9e, 0xd9, 0x84, 0x57,  \
    0x10, 0x39, 0x71, 0x63, 0x96, 0xf4, 0xaf, 0xc3, 0x78, 0x5d, 0xc7, 0x8c,  \
    0x80, 0xa9, 0x96, 0xd7, 0xc3, 0x87, 0x02, 0x96, 0x71, 0x7e, 0x5f, 0x2e,  \
    0x3c, 0x36, 0xae, 0x59, 0x92, 0xd7, 0x3a, 0x09, 0x78, 0xb9, 0xea, 0x6f,  \
    0xc2, 0x16, 0x42, 0xdc, 0x4b, 0x96, 0xad, 0x2c, 0xb2, 0x20, 0x23, 0x61,  \
    0x2d, 0x8d, 0xb5, 0x02, 0x1e, 0xe1, 0x6c, 0x81, 0x01, 0x3c, 0x5d, 0xcb,  \
    0xdd, 0x9b, 0x0e, 0xc0, 0x2f, 0x94, 0x12, 0xb2, 0xfe, 0x75, 0x75, 0x8b,  \
    0x74, 0x1e, 0x7a, 0x26, 0x0c, 0xb7, 0x81, 0x96, 0x81, 0x79, 0x6e, 0xdb,  \
    0xbc, 0x3a, 0xc4, 0x9e, 0x87, 0x09, 0x6e, 0xa0, 0xa6, 0xec, 0x8b, 0xa4,  \
    0x85, 0x71, 0xce, 0x04, 0xaf, 0x02, 0x81, 0x81, 0x00, 0xc2, 0xa7, 0x47,  \
    0x07, 0x48, 0x6a, 0xc8, 0xd4, 0xb3, 0x20, 0xe1, 0x98, 0xee, 0xff, 0x5a,  \
    0x6f, 0x30, 0x7a, 0xa5, 0x47, 0x40, 0xdc, 0x16, 0x62, 0x42, 0xf1, 0x2c,  \
    0xdc, 0xb8, 0xc7, 0x55, 0xde, 0x07, 0x3c, 0x9d, 0xb1, 0xd0, 0xdf, 0x02,  \
    0x82, 0xb0, 0x48, 0x58, 0xe1, 0x34, 0xab, 0xcf, 0xb4, 0x85, 0x23, 0x26,  \
    0x78, 0x4f, 0x7a, 0x59, 0x6f, 0xfb, 0x8c, 0x3d, 0xdf, 0x3d, 0x6c, 0x02,  \
    0x47, 0x9c, 0xe5, 0x5e, 0x49, 0xf1, 0x05, 0x0b, 0x1f, 0xbf, 0x48, 0x0f,  \
    0xdc, 0x10, 0xb9, 0x3d, 0x1d, 0x10, 0x77, 0x2a, 0x73, 0xf9, 0xdf, 0xbd,  \
    0xcd, 0xf3, 0x1f, 0xeb, 0x6e, 0x64, 0xca, 0x2b, 0x78, 0x4f, 0xf8, 0x73,  \
    0xc2, 0x10, 0xef, 0x79, 0x95, 0x33, 0x1e, 0x79, 0x35, 0x09, 0xff, 0x88,  \
    0x1b, 0xb4, 0x3e, 0x4c, 0xe1, 0x27, 0x2e, 0x75, 0x80, 0x58, 0x11, 0x03,  \
    0x21, 0x23, 0x96, 0x9a, 0xb5, 0x02, 0x81, 0x80, 0x05, 0x12, 0x64, 0x71,  \
    0x83, 0x00, 0x1c, 0xfe, 0xef, 0x83, 0xea, 0xdd, 0x2c, 0xc8, 0x2c, 0x00,  \
    0x62, 0x1e, 0x8f, 0x3a, 0xdb, 0x1c, 0xab, 0xd6, 0x34, 0x8b, 0xd1, 0xb2,  \
    0x5a, 0x4f, 0x3d, 0x37, 0x38, 0x02, 0xe0, 0xd7, 0x70, 0xc1, 0xb0, 0x47,  \
    0xe0, 0x08, 0x1a, 0x84, 0xec, 0x48, 0xc5, 0x7c, 0x76, 0x83, 0x12, 0x67,  \
    0xab, 0x7c, 0x9f, 0x90, 0x97, 0xc8, 0x8f, 0x07, 0xf4, 0xb3, 0x60, 0xf2,  \
    0x3f, 0x49, 0x18, 0xdb, 0x2e, 0x94, 0x6b, 0x53, 0x9e, 0xa2, 0x63, 0xde,  \
    0x63, 0xd9, 0xab, 0x21, 0x2e, 0x2d, 0x0a, 0xe0, 0xd0, 0xe8, 0xba, 0xc4,  \
    0x4c, 0x1e, 0xa5, 0xf5, 0x51, 0xa8, 0xc4, 0x92, 0xf8, 0x7f, 0x21, 0xe7,  \
    0x65, 0xbf, 0x0b, 0xe6, 0x01, 0xaf, 0x9c, 0x1d, 0x5b, 0x6c, 0x3f, 0x1c,  \
    0x2f, 0xa6, 0x0f, 0x68, 0x38, 0x8e, 0x85, 0xc4, 0x6c, 0x78, 0x2f, 0x6f,  \
    0x06, 0x21, 0x2e, 0x56                                                   \
}
/* END FILE */

/*
 * Test client Certificates
 *
 * Test client certificates are defined for each choice
 * of the following parameters:
 * - PEM or DER encoding
 * - RSA or EC key
 *
 * Things to add:
 * - hash type
 * - multiple EC curve types
 */

/* This is taken from tests/data_files/cli2.crt. */
/* BEGIN FILE string macro TEST_CLI_CRT_EC_PEM tests/data_files/cli2.crt */
#define TEST_CLI_CRT_EC_PEM                                                \
    "-----BEGIN CERTIFICATE-----\r\n"                                      \
    "MIIB3zCCAWOgAwIBAgIBDTAMBggqhkjOPQQDAgUAMD4xCzAJBgNVBAYTAk5MMREw\r\n" \
    "DwYDVQQKDAhQb2xhclNTTDEcMBoGA1UEAwwTUG9sYXJTU0wgVGVzdCBFQyBDQTAe\r\n" \
    "Fw0xOTAyMTAxNDQ0MDBaFw0yOTAyMTAxNDQ0MDBaMEExCzAJBgNVBAYTAk5MMREw\r\n" \
    "DwYDVQQKDAhQb2xhclNTTDEfMB0GA1UEAwwWUG9sYXJTU0wgVGVzdCBDbGllbnQg\r\n" \
    "MjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFflrrFz39Osu5O4gf8Sru7mU6zO\r\n" \
    "VVP2NA7MLuNjJQvfmOLzXGA2lsDVGBRw5X+f1UtFGOWwbNVc+JaPh3Cj5MejTTBL\r\n" \
    "MAkGA1UdEwQCMAAwHQYDVR0OBBYEFHoAX4Zk/OBd5REQO7LmO8QmP8/iMB8GA1Ud\r\n" \
    "IwQYMBaAFJ1tICRJAT8ry3i1Gbx+JMnb+zZ8MAwGCCqGSM49BAMCBQADaAAwZQIx\r\n" \
    "AMqme4DKMldUlplDET9Q6Eptre7uUWKhsLOF+zPkKDlfzpIkJYEFgcloDHGYw80u\r\n" \
    "IgIwNftyPXsabTqMM7iEHgVpX/GRozKklY9yQI/5eoA6gGW7Y+imuGR/oao5ySOb\r\n" \
    "a9Vk\r\n"                                                             \
    "-----END CERTIFICATE-----\r\n"
/* END FILE */

/* This is generated from tests/data_files/cli2.crt.der using `xxd -i`. */
/* BEGIN FILE binary macro TEST_CLI_CRT_EC_DER tests/data_files/cli2.crt.der */
#define TEST_CLI_CRT_EC_DER {                                                \
  0x30, 0x82, 0x01, 0xdf, 0x30, 0x82, 0x01, 0x63, 0xa0, 0x03, 0x02, 0x01,    \
  0x02, 0x02, 0x01, 0x0d, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,    \
  0x3d, 0x04, 0x03, 0x02, 0x05, 0x00, 0x30, 0x3e, 0x31, 0x0b, 0x30, 0x09,    \
  0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, 0x30,    \
  0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c, 0x61,    \
  0x72, 0x53, 0x53, 0x4c, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04,    \
  0x03, 0x0c, 0x13, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c, 0x20,    \
  0x54, 0x65, 0x73, 0x74, 0x20, 0x45, 0x43, 0x20, 0x43, 0x41, 0x30, 0x1e,    \
  0x17, 0x0d, 0x31, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34, 0x34,    \
  0x30, 0x30, 0x5a, 0x17, 0x0d, 0x32, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31,    \
  0x34, 0x34, 0x34, 0x30, 0x30, 0x5a, 0x30, 0x41, 0x31, 0x0b, 0x30, 0x09,    \
  0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, 0x30,    \
  0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c, 0x61,    \
  0x72, 0x53, 0x53, 0x4c, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04,    \
  0x03, 0x0c, 0x16, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c, 0x20,    \
  0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20,    \
  0x32, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,    \
  0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,    \
  0x03, 0x42, 0x00, 0x04, 0x57, 0xe5, 0xae, 0xb1, 0x73, 0xdf, 0xd3, 0xac,    \
  0xbb, 0x93, 0xb8, 0x81, 0xff, 0x12, 0xae, 0xee, 0xe6, 0x53, 0xac, 0xce,    \
  0x55, 0x53, 0xf6, 0x34, 0x0e, 0xcc, 0x2e, 0xe3, 0x63, 0x25, 0x0b, 0xdf,    \
  0x98, 0xe2, 0xf3, 0x5c, 0x60, 0x36, 0x96, 0xc0, 0xd5, 0x18, 0x14, 0x70,    \
  0xe5, 0x7f, 0x9f, 0xd5, 0x4b, 0x45, 0x18, 0xe5, 0xb0, 0x6c, 0xd5, 0x5c,    \
  0xf8, 0x96, 0x8f, 0x87, 0x70, 0xa3, 0xe4, 0xc7, 0xa3, 0x4d, 0x30, 0x4b,    \
  0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30,    \
  0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x7a, 0x00,    \
  0x5f, 0x86, 0x64, 0xfc, 0xe0, 0x5d, 0xe5, 0x11, 0x10, 0x3b, 0xb2, 0xe6,    \
  0x3b, 0xc4, 0x26, 0x3f, 0xcf, 0xe2, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d,    \
  0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x9d, 0x6d, 0x20, 0x24, 0x49,    \
  0x01, 0x3f, 0x2b, 0xcb, 0x78, 0xb5, 0x19, 0xbc, 0x7e, 0x24, 0xc9, 0xdb,    \
  0xfb, 0x36, 0x7c, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,    \
  0x04, 0x03, 0x02, 0x05, 0x00, 0x03, 0x68, 0x00, 0x30, 0x65, 0x02, 0x31,    \
  0x00, 0xca, 0xa6, 0x7b, 0x80, 0xca, 0x32, 0x57, 0x54, 0x96, 0x99, 0x43,    \
  0x11, 0x3f, 0x50, 0xe8, 0x4a, 0x6d, 0xad, 0xee, 0xee, 0x51, 0x62, 0xa1,    \
  0xb0, 0xb3, 0x85, 0xfb, 0x33, 0xe4, 0x28, 0x39, 0x5f, 0xce, 0x92, 0x24,    \
  0x25, 0x81, 0x05, 0x81, 0xc9, 0x68, 0x0c, 0x71, 0x98, 0xc3, 0xcd, 0x2e,    \
  0x22, 0x02, 0x30, 0x35, 0xfb, 0x72, 0x3d, 0x7b, 0x1a, 0x6d, 0x3a, 0x8c,    \
  0x33, 0xb8, 0x84, 0x1e, 0x05, 0x69, 0x5f, 0xf1, 0x91, 0xa3, 0x32, 0xa4,    \
  0x95, 0x8f, 0x72, 0x40, 0x8f, 0xf9, 0x7a, 0x80, 0x3a, 0x80, 0x65, 0xbb,    \
  0x63, 0xe8, 0xa6, 0xb8, 0x64, 0x7f, 0xa1, 0xaa, 0x39, 0xc9, 0x23, 0x9b,    \
  0x6b, 0xd5, 0x64                                                           \
}
/* END FILE */

/* This is taken from tests/data_files/cli2.key. */
/* BEGIN FILE string macro TEST_CLI_KEY_EC_PEM tests/data_files/cli2.key */
#define TEST_CLI_KEY_EC_PEM                                                \
    "-----BEGIN EC PRIVATE KEY-----\r\n"                                   \
    "MHcCAQEEIPb3hmTxZ3/mZI3vyk7p3U3wBf+WIop6hDhkFzJhmLcqoAoGCCqGSM49\r\n" \
    "AwEHoUQDQgAEV+WusXPf06y7k7iB/xKu7uZTrM5VU/Y0Dswu42MlC9+Y4vNcYDaW\r\n" \
    "wNUYFHDlf5/VS0UY5bBs1Vz4lo+HcKPkxw==\r\n"                             \
    "-----END EC PRIVATE KEY-----\r\n"
/* END FILE */

/* This is generated from tests/data_files/cli2.key.der using `xxd -i`. */
/* BEGIN FILE binary macro TEST_CLI_KEY_EC_DER tests/data_files/cli2.key.der */
#define TEST_CLI_KEY_EC_DER {                                                \
    0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0xf6, 0xf7, 0x86, 0x64, 0xf1,  \
    0x67, 0x7f, 0xe6, 0x64, 0x8d, 0xef, 0xca, 0x4e, 0xe9, 0xdd, 0x4d, 0xf0,  \
    0x05, 0xff, 0x96, 0x22, 0x8a, 0x7a, 0x84, 0x38, 0x64, 0x17, 0x32, 0x61,  \
    0x98, 0xb7, 0x2a, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,  \
    0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x57, 0xe5, 0xae,  \
    0xb1, 0x73, 0xdf, 0xd3, 0xac, 0xbb, 0x93, 0xb8, 0x81, 0xff, 0x12, 0xae,  \
    0xee, 0xe6, 0x53, 0xac, 0xce, 0x55, 0x53, 0xf6, 0x34, 0x0e, 0xcc, 0x2e,  \
    0xe3, 0x63, 0x25, 0x0b, 0xdf, 0x98, 0xe2, 0xf3, 0x5c, 0x60, 0x36, 0x96,  \
    0xc0, 0xd5, 0x18, 0x14, 0x70, 0xe5, 0x7f, 0x9f, 0xd5, 0x4b, 0x45, 0x18,  \
    0xe5, 0xb0, 0x6c, 0xd5, 0x5c, 0xf8, 0x96, 0x8f, 0x87, 0x70, 0xa3, 0xe4,  \
    0xc7                                                                     \
}
/* END FILE */

/* This is taken from tests/data_files/cli-rsa-sha256.crt. */
/* BEGIN FILE string macro TEST_CLI_CRT_RSA_PEM tests/data_files/cli-rsa-sha256.crt */
#define TEST_CLI_CRT_RSA_PEM                                               \
    "-----BEGIN CERTIFICATE-----\r\n"                                      \
    "MIIDPzCCAiegAwIBAgIBBDANBgkqhkiG9w0BAQsFADA7MQswCQYDVQQGEwJOTDER\r\n" \
    "MA8GA1UECgwIUG9sYXJTU0wxGTAXBgNVBAMMEFBvbGFyU1NMIFRlc3QgQ0EwHhcN\r\n" \
    "MTkwMjEwMTQ0NDA2WhcNMjkwMjEwMTQ0NDA2WjA8MQswCQYDVQQGEwJOTDERMA8G\r\n" \
    "A1UECgwIUG9sYXJTU0wxGjAYBgNVBAMMEVBvbGFyU1NMIENsaWVudCAyMIIBIjAN\r\n" \
    "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyHTEzLn5tXnpRdkUYLB9u5Pyax6f\r\n" \
    "M60Nj4o8VmXl3ETZzGaFB9X4J7BKNdBjngpuG7fa8H6r7gwQk4ZJGDTzqCrSV/Uu\r\n" \
    "1C93KYRhTYJQj6eVSHD1bk2y1RPD0hrt5kPqQhTrdOrA7R/UV06p86jt0uDBMHEw\r\n" \
    "MjDV0/YI0FZPRo7yX/k9Z5GIMC5Cst99++UMd//sMcB4j7/Cf8qtbCHWjdmLao5v\r\n" \
    "4Jv4EFbMs44TFeY0BGbH7vk2DmqV9gmaBmf0ZXH4yqSxJeD+PIs1BGe64E92hfx/\r\n" \
    "/DZrtenNLQNiTrM9AM+vdqBpVoNq0qjU51Bx5rU2BXcFbXvI5MT9TNUhXwIDAQAB\r\n" \
    "o00wSzAJBgNVHRMEAjAAMB0GA1UdDgQWBBRxoQBzckAvVHZeM/xSj7zx3WtGITAf\r\n" \
    "BgNVHSMEGDAWgBS0WuSls97SUva51aaVD+s+vMf9/zANBgkqhkiG9w0BAQsFAAOC\r\n" \
    "AQEAXidv1d4pLlBiKWED95rMycBdgDcgyNqJxakFkRfRyA2y1mlyTn7uBXRkNLY5\r\n" \
    "ZFzK82GCjk2Q2OD4RZSCPAJJqLpHHU34t71ciffvy2KK81YvrxczRhMAE64i+qna\r\n" \
    "yP3Td2XuWJR05PVPoSemsNELs9gWttdnYy3ce+EY2Y0n7Rsi7982EeLIAA7H6ca4\r\n" \
    "2Es/NUH//JZJT32OP0doMxeDRA+vplkKqTLLWf7dX26LIriBkBaRCgR5Yv9LBPFc\r\n" \
    "NOtpzu/LbrY7QFXKJMI+JXDudCsOn8KCmiA4d6Emisqfh3V3485l7HEQNcvLTxlD\r\n" \
    "6zDQyi0/ykYUYZkwQTK1N2Nvlw==\r\n"                                     \
    "-----END CERTIFICATE-----\r\n"
/* END FILE */

/* This was generated from tests/data_files/cli-rsa-sha256.crt.der
   using `xxd -i.` */
/* BEGIN FILE binary macro TEST_CLI_CRT_RSA_DER tests/data_files/cli-rsa-sha256.crt.der */
#define TEST_CLI_CRT_RSA_DER {                                               \
  0x30, 0x82, 0x03, 0x3f, 0x30, 0x82, 0x02, 0x27, 0xa0, 0x03, 0x02, 0x01,    \
  0x02, 0x02, 0x01, 0x04, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,    \
  0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x3b, 0x31, 0x0b, 0x30,    \
  0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11,    \
  0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c,    \
  0x61, 0x72, 0x53, 0x53, 0x4c, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55,    \
  0x04, 0x03, 0x0c, 0x10, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c,    \
  0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d,    \
  0x31, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34, 0x34, 0x30, 0x36,    \
  0x5a, 0x17, 0x0d, 0x32, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34,    \
  0x34, 0x30, 0x36, 0x5a, 0x30, 0x3c, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,    \
  0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, 0x30, 0x0f, 0x06,    \
  0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53,    \
  0x53, 0x4c, 0x31, 0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,    \
  0x11, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c, 0x20, 0x43, 0x6c,    \
  0x69, 0x65, 0x6e, 0x74, 0x20, 0x32, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d,    \
  0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,    \
  0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82,    \
  0x01, 0x01, 0x00, 0xc8, 0x74, 0xc4, 0xcc, 0xb9, 0xf9, 0xb5, 0x79, 0xe9,    \
  0x45, 0xd9, 0x14, 0x60, 0xb0, 0x7d, 0xbb, 0x93, 0xf2, 0x6b, 0x1e, 0x9f,    \
  0x33, 0xad, 0x0d, 0x8f, 0x8a, 0x3c, 0x56, 0x65, 0xe5, 0xdc, 0x44, 0xd9,    \
  0xcc, 0x66, 0x85, 0x07, 0xd5, 0xf8, 0x27, 0xb0, 0x4a, 0x35, 0xd0, 0x63,    \
  0x9e, 0x0a, 0x6e, 0x1b, 0xb7, 0xda, 0xf0, 0x7e, 0xab, 0xee, 0x0c, 0x10,    \
  0x93, 0x86, 0x49, 0x18, 0x34, 0xf3, 0xa8, 0x2a, 0xd2, 0x57, 0xf5, 0x2e,    \
  0xd4, 0x2f, 0x77, 0x29, 0x84, 0x61, 0x4d, 0x82, 0x50, 0x8f, 0xa7, 0x95,    \
  0x48, 0x70, 0xf5, 0x6e, 0x4d, 0xb2, 0xd5, 0x13, 0xc3, 0xd2, 0x1a, 0xed,    \
  0xe6, 0x43, 0xea, 0x42, 0x14, 0xeb, 0x74, 0xea, 0xc0, 0xed, 0x1f, 0xd4,    \
  0x57, 0x4e, 0xa9, 0xf3, 0xa8, 0xed, 0xd2, 0xe0, 0xc1, 0x30, 0x71, 0x30,    \
  0x32, 0x30, 0xd5, 0xd3, 0xf6, 0x08, 0xd0, 0x56, 0x4f, 0x46, 0x8e, 0xf2,    \
  0x5f, 0xf9, 0x3d, 0x67, 0x91, 0x88, 0x30, 0x2e, 0x42, 0xb2, 0xdf, 0x7d,    \
  0xfb, 0xe5, 0x0c, 0x77, 0xff, 0xec, 0x31, 0xc0, 0x78, 0x8f, 0xbf, 0xc2,    \
  0x7f, 0xca, 0xad, 0x6c, 0x21, 0xd6, 0x8d, 0xd9, 0x8b, 0x6a, 0x8e, 0x6f,    \
  0xe0, 0x9b, 0xf8, 0x10, 0x56, 0xcc, 0xb3, 0x8e, 0x13, 0x15, 0xe6, 0x34,    \
  0x04, 0x66, 0xc7, 0xee, 0xf9, 0x36, 0x0e, 0x6a, 0x95, 0xf6, 0x09, 0x9a,    \
  0x06, 0x67, 0xf4, 0x65, 0x71, 0xf8, 0xca, 0xa4, 0xb1, 0x25, 0xe0, 0xfe,    \
  0x3c, 0x8b, 0x35, 0x04, 0x67, 0xba, 0xe0, 0x4f, 0x76, 0x85, 0xfc, 0x7f,    \
  0xfc, 0x36, 0x6b, 0xb5, 0xe9, 0xcd, 0x2d, 0x03, 0x62, 0x4e, 0xb3, 0x3d,    \
  0x00, 0xcf, 0xaf, 0x76, 0xa0, 0x69, 0x56, 0x83, 0x6a, 0xd2, 0xa8, 0xd4,    \
  0xe7, 0x50, 0x71, 0xe6, 0xb5, 0x36, 0x05, 0x77, 0x05, 0x6d, 0x7b, 0xc8,    \
  0xe4, 0xc4, 0xfd, 0x4c, 0xd5, 0x21, 0x5f, 0x02, 0x03, 0x01, 0x00, 0x01,    \
  0xa3, 0x4d, 0x30, 0x4b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04,    \
  0x02, 0x30, 0x00, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16,    \
  0x04, 0x14, 0x71, 0xa1, 0x00, 0x73, 0x72, 0x40, 0x2f, 0x54, 0x76, 0x5e,    \
  0x33, 0xfc, 0x52, 0x8f, 0xbc, 0xf1, 0xdd, 0x6b, 0x46, 0x21, 0x30, 0x1f,    \
  0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xb4,    \
  0x5a, 0xe4, 0xa5, 0xb3, 0xde, 0xd2, 0x52, 0xf6, 0xb9, 0xd5, 0xa6, 0x95,    \
  0x0f, 0xeb, 0x3e, 0xbc, 0xc7, 0xfd, 0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a,    \
  0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82,    \
  0x01, 0x01, 0x00, 0x5e, 0x27, 0x6f, 0xd5, 0xde, 0x29, 0x2e, 0x50, 0x62,    \
  0x29, 0x61, 0x03, 0xf7, 0x9a, 0xcc, 0xc9, 0xc0, 0x5d, 0x80, 0x37, 0x20,    \
  0xc8, 0xda, 0x89, 0xc5, 0xa9, 0x05, 0x91, 0x17, 0xd1, 0xc8, 0x0d, 0xb2,    \
  0xd6, 0x69, 0x72, 0x4e, 0x7e, 0xee, 0x05, 0x74, 0x64, 0x34, 0xb6, 0x39,    \
  0x64, 0x5c, 0xca, 0xf3, 0x61, 0x82, 0x8e, 0x4d, 0x90, 0xd8, 0xe0, 0xf8,    \
  0x45, 0x94, 0x82, 0x3c, 0x02, 0x49, 0xa8, 0xba, 0x47, 0x1d, 0x4d, 0xf8,    \
  0xb7, 0xbd, 0x5c, 0x89, 0xf7, 0xef, 0xcb, 0x62, 0x8a, 0xf3, 0x56, 0x2f,    \
  0xaf, 0x17, 0x33, 0x46, 0x13, 0x00, 0x13, 0xae, 0x22, 0xfa, 0xa9, 0xda,    \
  0xc8, 0xfd, 0xd3, 0x77, 0x65, 0xee, 0x58, 0x94, 0x74, 0xe4, 0xf5, 0x4f,    \
  0xa1, 0x27, 0xa6, 0xb0, 0xd1, 0x0b, 0xb3, 0xd8, 0x16, 0xb6, 0xd7, 0x67,    \
  0x63, 0x2d, 0xdc, 0x7b, 0xe1, 0x18, 0xd9, 0x8d, 0x27, 0xed, 0x1b, 0x22,    \
  0xef, 0xdf, 0x36, 0x11, 0xe2, 0xc8, 0x00, 0x0e, 0xc7, 0xe9, 0xc6, 0xb8,    \
  0xd8, 0x4b, 0x3f, 0x35, 0x41, 0xff, 0xfc, 0x96, 0x49, 0x4f, 0x7d, 0x8e,    \
  0x3f, 0x47, 0x68, 0x33, 0x17, 0x83, 0x44, 0x0f, 0xaf, 0xa6, 0x59, 0x0a,    \
  0xa9, 0x32, 0xcb, 0x59, 0xfe, 0xdd, 0x5f, 0x6e, 0x8b, 0x22, 0xb8, 0x81,    \
  0x90, 0x16, 0x91, 0x0a, 0x04, 0x79, 0x62, 0xff, 0x4b, 0x04, 0xf1, 0x5c,    \
  0x34, 0xeb, 0x69, 0xce, 0xef, 0xcb, 0x6e, 0xb6, 0x3b, 0x40, 0x55, 0xca,    \
  0x24, 0xc2, 0x3e, 0x25, 0x70, 0xee, 0x74, 0x2b, 0x0e, 0x9f, 0xc2, 0x82,    \
  0x9a, 0x20, 0x38, 0x77, 0xa1, 0x26, 0x8a, 0xca, 0x9f, 0x87, 0x75, 0x77,    \
  0xe3, 0xce, 0x65, 0xec, 0x71, 0x10, 0x35, 0xcb, 0xcb, 0x4f, 0x19, 0x43,    \
  0xeb, 0x30, 0xd0, 0xca, 0x2d, 0x3f, 0xca, 0x46, 0x14, 0x61, 0x99, 0x30,    \
  0x41, 0x32, 0xb5, 0x37, 0x63, 0x6f, 0x97                                   \
}
/* END FILE */

/* This is taken from tests/data_files/cli-rsa.key. */
/* BEGIN FILE string macro TEST_CLI_KEY_RSA_PEM tests/data_files/cli-rsa.key */
#define TEST_CLI_KEY_RSA_PEM                                               \
    "-----BEGIN RSA PRIVATE KEY-----\r\n"                                  \
    "MIIEpAIBAAKCAQEAyHTEzLn5tXnpRdkUYLB9u5Pyax6fM60Nj4o8VmXl3ETZzGaF\r\n" \
    "B9X4J7BKNdBjngpuG7fa8H6r7gwQk4ZJGDTzqCrSV/Uu1C93KYRhTYJQj6eVSHD1\r\n" \
    "bk2y1RPD0hrt5kPqQhTrdOrA7R/UV06p86jt0uDBMHEwMjDV0/YI0FZPRo7yX/k9\r\n" \
    "Z5GIMC5Cst99++UMd//sMcB4j7/Cf8qtbCHWjdmLao5v4Jv4EFbMs44TFeY0BGbH\r\n" \
    "7vk2DmqV9gmaBmf0ZXH4yqSxJeD+PIs1BGe64E92hfx//DZrtenNLQNiTrM9AM+v\r\n" \
    "dqBpVoNq0qjU51Bx5rU2BXcFbXvI5MT9TNUhXwIDAQABAoIBAGdNtfYDiap6bzst\r\n" \
    "yhCiI8m9TtrhZw4MisaEaN/ll3XSjaOG2dvV6xMZCMV+5TeXDHOAZnY18Yi18vzz\r\n" \
    "4Ut2TnNFzizCECYNaA2fST3WgInnxUkV3YXAyP6CNxJaCmv2aA0yFr2kFVSeaKGt\r\n" \
    "ymvljNp2NVkvm7Th8fBQBO7I7AXhz43k0mR7XmPgewe8ApZOG3hstkOaMvbWAvWA\r\n" \
    "zCZupdDjZYjOJqlA4eEA4H8/w7F83r5CugeBE8LgEREjLPiyejrU5H1fubEY+h0d\r\n" \
    "l5HZBJ68ybTXfQ5U9o/QKA3dd0toBEhhdRUDGzWtjvwkEQfqF1reGWj/tod/gCpf\r\n" \
    "DFi6X0ECgYEA4wOv/pjSC3ty6TuOvKX2rOUiBrLXXv2JSxZnMoMiWI5ipLQt+RYT\r\n" \
    "VPafL/m7Dn6MbwjayOkcZhBwk5CNz5A6Q4lJ64Mq/lqHznRCQQ2Mc1G8eyDF/fYL\r\n" \
    "Ze2pLvwP9VD5jTc2miDfw+MnvJhywRRLcemDFP8k4hQVtm8PMp3ZmNECgYEA4gz7\r\n" \
    "wzObR4gn8ibe617uQPZjWzUj9dUHYd+in1gwBCIrtNnaRn9I9U/Q6tegRYpii4ys\r\n" \
    "c176NmU+umy6XmuSKV5qD9bSpZWG2nLFnslrN15Lm3fhZxoeMNhBaEDTnLT26yoi\r\n" \
    "33gp0mSSWy94ZEqipms+ULF6sY1ZtFW6tpGFoy8CgYAQHhnnvJflIs2ky4q10B60\r\n" \
    "ZcxFp3rtDpkp0JxhFLhiizFrujMtZSjYNm5U7KkgPVHhLELEUvCmOnKTt4ap/vZ0\r\n" \
    "BxJNe1GZH3pW6SAvGDQpl9sG7uu/vTFP+lCxukmzxB0DrrDcvorEkKMom7ZCCRvW\r\n" \
    "KZsZ6YeH2Z81BauRj218kQKBgQCUV/DgKP2985xDTT79N08jUo3hTP5MVYCCuj/+\r\n" \
    "UeEw1TvZcx3LJby7P6Xad6a1/BqveaGyFKIfEFIaBUBItk801sDDpDaYc4gL00Xc\r\n" \
    "7lFuBHOZkxJYlss5QrGpuOEl9ZwUt5IrFLBdYaKqNHzNVC1pCPfb/JyH6Dr2HUxq\r\n" \
    "gxUwAQKBgQCcU6G2L8AG9d9c0UpOyL1tMvFe5Ttw0KjlQVdsh1MP6yigYo9DYuwu\r\n" \
    "bHFVW2r0dBTqegP2/KTOxKzaHfC1qf0RGDsUoJCNJrd1cwoCLG8P2EF4w3OBrKqv\r\n" \
    "8u4ytY0F+Vlanj5lm3TaoHSVF1+NWPyOTiwevIECGKwSxvlki4fDAA==\r\n"         \
    "-----END RSA PRIVATE KEY-----\r\n"/* END FILE */

/* This was generated from tests/data_files/cli-rsa.key.der using `xxd -i`. */
/* BEGIN FILE binary macro TEST_CLI_KEY_RSA_DER tests/data_files/cli-rsa.key.der */
#define TEST_CLI_KEY_RSA_DER {                                               \
    0x30, 0x82, 0x04, 0xa4, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,  \
    0xc8, 0x74, 0xc4, 0xcc, 0xb9, 0xf9, 0xb5, 0x79, 0xe9, 0x45, 0xd9, 0x14,  \
    0x60, 0xb0, 0x7d, 0xbb, 0x93, 0xf2, 0x6b, 0x1e, 0x9f, 0x33, 0xad, 0x0d,  \
    0x8f, 0x8a, 0x3c, 0x56, 0x65, 0xe5, 0xdc, 0x44, 0xd9, 0xcc, 0x66, 0x85,  \
    0x07, 0xd5, 0xf8, 0x27, 0xb0, 0x4a, 0x35, 0xd0, 0x63, 0x9e, 0x0a, 0x6e,  \
    0x1b, 0xb7, 0xda, 0xf0, 0x7e, 0xab, 0xee, 0x0c, 0x10, 0x93, 0x86, 0x49,  \
    0x18, 0x34, 0xf3, 0xa8, 0x2a, 0xd2, 0x57, 0xf5, 0x2e, 0xd4, 0x2f, 0x77,  \
    0x29, 0x84, 0x61, 0x4d, 0x82, 0x50, 0x8f, 0xa7, 0x95, 0x48, 0x70, 0xf5,  \
    0x6e, 0x4d, 0xb2, 0xd5, 0x13, 0xc3, 0xd2, 0x1a, 0xed, 0xe6, 0x43, 0xea,  \
    0x42, 0x14, 0xeb, 0x74, 0xea, 0xc0, 0xed, 0x1f, 0xd4, 0x57, 0x4e, 0xa9,  \
    0xf3, 0xa8, 0xed, 0xd2, 0xe0, 0xc1, 0x30, 0x71, 0x30, 0x32, 0x30, 0xd5,  \
    0xd3, 0xf6, 0x08, 0xd0, 0x56, 0x4f, 0x46, 0x8e, 0xf2, 0x5f, 0xf9, 0x3d,  \
    0x67, 0x91, 0x88, 0x30, 0x2e, 0x42, 0xb2, 0xdf, 0x7d, 0xfb, 0xe5, 0x0c,  \
    0x77, 0xff, 0xec, 0x31, 0xc0, 0x78, 0x8f, 0xbf, 0xc2, 0x7f, 0xca, 0xad,  \
    0x6c, 0x21, 0xd6, 0x8d, 0xd9, 0x8b, 0x6a, 0x8e, 0x6f, 0xe0, 0x9b, 0xf8,  \
    0x10, 0x56, 0xcc, 0xb3, 0x8e, 0x13, 0x15, 0xe6, 0x34, 0x04, 0x66, 0xc7,  \
    0xee, 0xf9, 0x36, 0x0e, 0x6a, 0x95, 0xf6, 0x09, 0x9a, 0x06, 0x67, 0xf4,  \
    0x65, 0x71, 0xf8, 0xca, 0xa4, 0xb1, 0x25, 0xe0, 0xfe, 0x3c, 0x8b, 0x35,  \
    0x04, 0x67, 0xba, 0xe0, 0x4f, 0x76, 0x85, 0xfc, 0x7f, 0xfc, 0x36, 0x6b,  \
    0xb5, 0xe9, 0xcd, 0x2d, 0x03, 0x62, 0x4e, 0xb3, 0x3d, 0x00, 0xcf, 0xaf,  \
    0x76, 0xa0, 0x69, 0x56, 0x83, 0x6a, 0xd2, 0xa8, 0xd4, 0xe7, 0x50, 0x71,  \
    0xe6, 0xb5, 0x36, 0x05, 0x77, 0x05, 0x6d, 0x7b, 0xc8, 0xe4, 0xc4, 0xfd,  \
    0x4c, 0xd5, 0x21, 0x5f, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01,  \
    0x00, 0x67, 0x4d, 0xb5, 0xf6, 0x03, 0x89, 0xaa, 0x7a, 0x6f, 0x3b, 0x2d,  \
    0xca, 0x10, 0xa2, 0x23, 0xc9, 0xbd, 0x4e, 0xda, 0xe1, 0x67, 0x0e, 0x0c,  \
    0x8a, 0xc6, 0x84, 0x68, 0xdf, 0xe5, 0x97, 0x75, 0xd2, 0x8d, 0xa3, 0x86,  \
    0xd9, 0xdb, 0xd5, 0xeb, 0x13, 0x19, 0x08, 0xc5, 0x7e, 0xe5, 0x37, 0x97,  \
    0x0c, 0x73, 0x80, 0x66, 0x76, 0x35, 0xf1, 0x88, 0xb5, 0xf2, 0xfc, 0xf3,  \
    0xe1, 0x4b, 0x76, 0x4e, 0x73, 0x45, 0xce, 0x2c, 0xc2, 0x10, 0x26, 0x0d,  \
    0x68, 0x0d, 0x9f, 0x49, 0x3d, 0xd6, 0x80, 0x89, 0xe7, 0xc5, 0x49, 0x15,  \
    0xdd, 0x85, 0xc0, 0xc8, 0xfe, 0x82, 0x37, 0x12, 0x5a, 0x0a, 0x6b, 0xf6,  \
    0x68, 0x0d, 0x32, 0x16, 0xbd, 0xa4, 0x15, 0x54, 0x9e, 0x68, 0xa1, 0xad,  \
    0xca, 0x6b, 0xe5, 0x8c, 0xda, 0x76, 0x35, 0x59, 0x2f, 0x9b, 0xb4, 0xe1,  \
    0xf1, 0xf0, 0x50, 0x04, 0xee, 0xc8, 0xec, 0x05, 0xe1, 0xcf, 0x8d, 0xe4,  \
    0xd2, 0x64, 0x7b, 0x5e, 0x63, 0xe0, 0x7b, 0x07, 0xbc, 0x02, 0x96, 0x4e,  \
    0x1b, 0x78, 0x6c, 0xb6, 0x43, 0x9a, 0x32, 0xf6, 0xd6, 0x02, 0xf5, 0x80,  \
    0xcc, 0x26, 0x6e, 0xa5, 0xd0, 0xe3, 0x65, 0x88, 0xce, 0x26, 0xa9, 0x40,  \
    0xe1, 0xe1, 0x00, 0xe0, 0x7f, 0x3f, 0xc3, 0xb1, 0x7c, 0xde, 0xbe, 0x42,  \
    0xba, 0x07, 0x81, 0x13, 0xc2, 0xe0, 0x11, 0x11, 0x23, 0x2c, 0xf8, 0xb2,  \
    0x7a, 0x3a, 0xd4, 0xe4, 0x7d, 0x5f, 0xb9, 0xb1, 0x18, 0xfa, 0x1d, 0x1d,  \
    0x97, 0x91, 0xd9, 0x04, 0x9e, 0xbc, 0xc9, 0xb4, 0xd7, 0x7d, 0x0e, 0x54,  \
    0xf6, 0x8f, 0xd0, 0x28, 0x0d, 0xdd, 0x77, 0x4b, 0x68, 0x04, 0x48, 0x61,  \
    0x75, 0x15, 0x03, 0x1b, 0x35, 0xad, 0x8e, 0xfc, 0x24, 0x11, 0x07, 0xea,  \
    0x17, 0x5a, 0xde, 0x19, 0x68, 0xff, 0xb6, 0x87, 0x7f, 0x80, 0x2a, 0x5f,  \
    0x0c, 0x58, 0xba, 0x5f, 0x41, 0x02, 0x81, 0x81, 0x00, 0xe3, 0x03, 0xaf,  \
    0xfe, 0x98, 0xd2, 0x0b, 0x7b, 0x72, 0xe9, 0x3b, 0x8e, 0xbc, 0xa5, 0xf6,  \
    0xac, 0xe5, 0x22, 0x06, 0xb2, 0xd7, 0x5e, 0xfd, 0x89, 0x4b, 0x16, 0x67,  \
    0x32, 0x83, 0x22, 0x58, 0x8e, 0x62, 0xa4, 0xb4, 0x2d, 0xf9, 0x16, 0x13,  \
    0x54, 0xf6, 0x9f, 0x2f, 0xf9, 0xbb, 0x0e, 0x7e, 0x8c, 0x6f, 0x08, 0xda,  \
    0xc8, 0xe9, 0x1c, 0x66, 0x10, 0x70, 0x93, 0x90, 0x8d, 0xcf, 0x90, 0x3a,  \
    0x43, 0x89, 0x49, 0xeb, 0x83, 0x2a, 0xfe, 0x5a, 0x87, 0xce, 0x74, 0x42,  \
    0x41, 0x0d, 0x8c, 0x73, 0x51, 0xbc, 0x7b, 0x20, 0xc5, 0xfd, 0xf6, 0x0b,  \
    0x65, 0xed, 0xa9, 0x2e, 0xfc, 0x0f, 0xf5, 0x50, 0xf9, 0x8d, 0x37, 0x36,  \
    0x9a, 0x20, 0xdf, 0xc3, 0xe3, 0x27, 0xbc, 0x98, 0x72, 0xc1, 0x14, 0x4b,  \
    0x71, 0xe9, 0x83, 0x14, 0xff, 0x24, 0xe2, 0x14, 0x15, 0xb6, 0x6f, 0x0f,  \
    0x32, 0x9d, 0xd9, 0x98, 0xd1, 0x02, 0x81, 0x81, 0x00, 0xe2, 0x0c, 0xfb,  \
    0xc3, 0x33, 0x9b, 0x47, 0x88, 0x27, 0xf2, 0x26, 0xde, 0xeb, 0x5e, 0xee,  \
    0x40, 0xf6, 0x63, 0x5b, 0x35, 0x23, 0xf5, 0xd5, 0x07, 0x61, 0xdf, 0xa2,  \
    0x9f, 0x58, 0x30, 0x04, 0x22, 0x2b, 0xb4, 0xd9, 0xda, 0x46, 0x7f, 0x48,  \
    0xf5, 0x4f, 0xd0, 0xea, 0xd7, 0xa0, 0x45, 0x8a, 0x62, 0x8b, 0x8c, 0xac,  \
    0x73, 0x5e, 0xfa, 0x36, 0x65, 0x3e, 0xba, 0x6c, 0xba, 0x5e, 0x6b, 0x92,  \
    0x29, 0x5e, 0x6a, 0x0f, 0xd6, 0xd2, 0xa5, 0x95, 0x86, 0xda, 0x72, 0xc5,  \
    0x9e, 0xc9, 0x6b, 0x37, 0x5e, 0x4b, 0x9b, 0x77, 0xe1, 0x67, 0x1a, 0x1e,  \
    0x30, 0xd8, 0x41, 0x68, 0x40, 0xd3, 0x9c, 0xb4, 0xf6, 0xeb, 0x2a, 0x22,  \
    0xdf, 0x78, 0x29, 0xd2, 0x64, 0x92, 0x5b, 0x2f, 0x78, 0x64, 0x4a, 0xa2,  \
    0xa6, 0x6b, 0x3e, 0x50, 0xb1, 0x7a, 0xb1, 0x8d, 0x59, 0xb4, 0x55, 0xba,  \
    0xb6, 0x91, 0x85, 0xa3, 0x2f, 0x02, 0x81, 0x80, 0x10, 0x1e, 0x19, 0xe7,  \
    0xbc, 0x97, 0xe5, 0x22, 0xcd, 0xa4, 0xcb, 0x8a, 0xb5, 0xd0, 0x1e, 0xb4,  \
    0x65, 0xcc, 0x45, 0xa7, 0x7a, 0xed, 0x0e, 0x99, 0x29, 0xd0, 0x9c, 0x61,  \
    0x14, 0xb8, 0x62, 0x8b, 0x31, 0x6b, 0xba, 0x33, 0x2d, 0x65, 0x28, 0xd8,  \
    0x36, 0x6e, 0x54, 0xec, 0xa9, 0x20, 0x3d, 0x51, 0xe1, 0x2c, 0x42, 0xc4,  \
    0x52, 0xf0, 0xa6, 0x3a, 0x72, 0x93, 0xb7, 0x86, 0xa9, 0xfe, 0xf6, 0x74,  \
    0x07, 0x12, 0x4d, 0x7b, 0x51, 0x99, 0x1f, 0x7a, 0x56, 0xe9, 0x20, 0x2f,  \
    0x18, 0x34, 0x29, 0x97, 0xdb, 0x06, 0xee, 0xeb, 0xbf, 0xbd, 0x31, 0x4f,  \
    0xfa, 0x50, 0xb1, 0xba, 0x49, 0xb3, 0xc4, 0x1d, 0x03, 0xae, 0xb0, 0xdc,  \
    0xbe, 0x8a, 0xc4, 0x90, 0xa3, 0x28, 0x9b, 0xb6, 0x42, 0x09, 0x1b, 0xd6,  \
    0x29, 0x9b, 0x19, 0xe9, 0x87, 0x87, 0xd9, 0x9f, 0x35, 0x05, 0xab, 0x91,  \
    0x8f, 0x6d, 0x7c, 0x91, 0x02, 0x81, 0x81, 0x00, 0x94, 0x57, 0xf0, 0xe0,  \
    0x28, 0xfd, 0xbd, 0xf3, 0x9c, 0x43, 0x4d, 0x3e, 0xfd, 0x37, 0x4f, 0x23,  \
    0x52, 0x8d, 0xe1, 0x4c, 0xfe, 0x4c, 0x55, 0x80, 0x82, 0xba, 0x3f, 0xfe,  \
    0x51, 0xe1, 0x30, 0xd5, 0x3b, 0xd9, 0x73, 0x1d, 0xcb, 0x25, 0xbc, 0xbb,  \
    0x3f, 0xa5, 0xda, 0x77, 0xa6, 0xb5, 0xfc, 0x1a, 0xaf, 0x79, 0xa1, 0xb2,  \
    0x14, 0xa2, 0x1f, 0x10, 0x52, 0x1a, 0x05, 0x40, 0x48, 0xb6, 0x4f, 0x34,  \
    0xd6, 0xc0, 0xc3, 0xa4, 0x36, 0x98, 0x73, 0x88, 0x0b, 0xd3, 0x45, 0xdc,  \
    0xee, 0x51, 0x6e, 0x04, 0x73, 0x99, 0x93, 0x12, 0x58, 0x96, 0xcb, 0x39,  \
    0x42, 0xb1, 0xa9, 0xb8, 0xe1, 0x25, 0xf5, 0x9c, 0x14, 0xb7, 0x92, 0x2b,  \
    0x14, 0xb0, 0x5d, 0x61, 0xa2, 0xaa, 0x34, 0x7c, 0xcd, 0x54, 0x2d, 0x69,  \
    0x08, 0xf7, 0xdb, 0xfc, 0x9c, 0x87, 0xe8, 0x3a, 0xf6, 0x1d, 0x4c, 0x6a,  \
    0x83, 0x15, 0x30, 0x01, 0x02, 0x81, 0x81, 0x00, 0x9c, 0x53, 0xa1, 0xb6,  \
    0x2f, 0xc0, 0x06, 0xf5, 0xdf, 0x5c, 0xd1, 0x4a, 0x4e, 0xc8, 0xbd, 0x6d,  \
    0x32, 0xf1, 0x5e, 0xe5, 0x3b, 0x70, 0xd0, 0xa8, 0xe5, 0x41, 0x57, 0x6c,  \
    0x87, 0x53, 0x0f, 0xeb, 0x28, 0xa0, 0x62, 0x8f, 0x43, 0x62, 0xec, 0x2e,  \
    0x6c, 0x71, 0x55, 0x5b, 0x6a, 0xf4, 0x74, 0x14, 0xea, 0x7a, 0x03, 0xf6,  \
    0xfc, 0xa4, 0xce, 0xc4, 0xac, 0xda, 0x1d, 0xf0, 0xb5, 0xa9, 0xfd, 0x11,  \
    0x18, 0x3b, 0x14, 0xa0, 0x90, 0x8d, 0x26, 0xb7, 0x75, 0x73, 0x0a, 0x02,  \
    0x2c, 0x6f, 0x0f, 0xd8, 0x41, 0x78, 0xc3, 0x73, 0x81, 0xac, 0xaa, 0xaf,  \
    0xf2, 0xee, 0x32, 0xb5, 0x8d, 0x05, 0xf9, 0x59, 0x5a, 0x9e, 0x3e, 0x65,  \
    0x9b, 0x74, 0xda, 0xa0, 0x74, 0x95, 0x17, 0x5f, 0x8d, 0x58, 0xfc, 0x8e,  \
    0x4e, 0x2c, 0x1e, 0xbc, 0x81, 0x02, 0x18, 0xac, 0x12, 0xc6, 0xf9, 0x64,  \
    0x8b, 0x87, 0xc3, 0x00                                                   \
}
/* END FILE */

/* 
    SPHINCS+ certificates
 */
#define TEST_CA_CRT_SPHINCS_SHAKE256_PEM \
"-----BEGIN CERTIFICATE-----\r\n"	\
"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\r\n"	\
"AAAAAAAAAAAAAAAAAAAAAAAAAA==\r\n"	\
"-----END CERTIFICATE-----\r\n"	

#define TEST_SRV_KEY_SPHINCS_SHAKE256_PEM                               \
"-----BEGIN SPHINCS PRIVATE KEY-----\r\n"	\
"ME4EEQCiNT9BjDGq+QjKxVkV4VRiBBEAu8PbUpM0gqNSFD9TUQ+a/wQRAKkz2Iln\r\n"	\
"N5h8ipthIM5YArEEEDFQCGEj+z2ER48JNtSxckkCAQo=\r\n"	\
"-----END SPHINCS PRIVATE KEY-----\r\n"	

#define TEST_SRV_CRT_SPHINCS_SHAKE256_PEM                               \
"-----BEGIN CERTIFICATE-----\r\n"	\
"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\r\n"	\
"AAAAAAAAAAAAAAAAAAAA\r\n"	\
"-----END CERTIFICATE-----\r\n"	

#define TEST_CA_CRT_SPHINCS_SHA256_PEM                                  \
"-----BEGIN CERTIFICATE-----\r\n"	\
"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\r\n"	\
"-----END CERTIFICATE-----\r\n"

#define TEST_SRV_KEY_SPHINCS_SHA256_PEM                                 \
"-----BEGIN SPHINCS PRIVATE KEY-----\r\n"	\
"ME0EEEGGqjyYvp0yp7bUVWwzHMUEEDzKMWckefNGeaJmIPBhvNEEEQD9u7vDSeTc\r\n"	\
"H0HdmntAiXirBBEA0zXHpLlS1ghPGy+l/504jgIBBg==\r\n"	\
"-----END SPHINCS PRIVATE KEY-----\r\n"

#define TEST_SRV_CRT_SPHINCS_SHA256_PEM                                 \
"-----BEGIN CERTIFICATE-----\r\n"	\
"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\r\n"	\
"-----END CERTIFICATE-----\r\n"



/*
 * Dilithium certificates
 * 
 */
 
#define TEST_CA_CRT_DILITHIUM_SHAKE256_PEM \
"-----BEGIN CERTIFICATE-----\r\n"	\
"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\r\n"	\
"-----END CERTIFICATE-----\r\n"	

#define TEST_SRV_KEY_DILITHIUM_SHAKE256_PEM \
"-----BEGIN DILITHIUM PRIVATE KEY-----\r\n"	\
"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\r\n"	\
"CncqmrD1xR5uqzGp43J6QMPp0Y2DCXxVMMj/dj2lN6W+abCUPmk75nB6EAkin6Ba\r\n"	\
"4fY3tRBIP6v1MUNL0EVkJg56vP41/9sSTI0awYErEtjgkDk/rrdQF+nZk3JpNMOa\r\n"	\
"3RczeG0VuccQMZeb9LqdCZpdItpccJU2vajGujpYgDDSyOw+0gKdv2gPusHpxKPY\r\n"	\
"wV2Dip08glc6/bAe4uWCsOlCbD8vISbnK3/JvpQAeNZLC99C2sJtJpIHNY1HNTmZ\r\n"	\
"7gVYtp9WtmjfgBAHdV7+0MagL9SwwI2E82NNCV57zwEpDfxnfFf6n6QEJwmG5SZS\r\n"	\
"SB2QXy6WYqVd09XSJRsilDMPeDh+VkHcZY3Y0E5ioLDix66FnipezwUImCKbTNXY\r\n"	\
"7tvy1Z8gtbx63mzVU20X+xM4QtnvRxKIFTsIz+VTczTv9utXUpZVamYVzb70jXdY\r\n"	\
"Ag9Vab6vJVPRlzCXa6hf4XLA8lPVdPiP0Klth9ObEmy+s4z6kJ1EwjPpReDtFyko\r\n"	\
"JLxd+y65nSOBSQ7tvJjsjmcnAgsV38fHnxUzqy8Ohm7hRnqrHdIB2+YqRz2dyIfz\r\n"	\
"8Kb0ErWE1Ud6GpokxKlUqiqOrX182LdWXGtZ8U8H+KQOuS7kW0QKgHzhEnKAjW8g\r\n"	\
"AxWubL0cQEIMzfEs6dt/KOuyctAkWMJX+pgWIDaz1xROTQaBcgPLGUlG7gOKghcr\r\n"	\
"TCQsmZPUE9Bchr0wo/Zvcs+fKOJZKTiVsDWcUeaBZFySse7oPoz/YPZU31UQln1+\r\n"	\
"hDzzF33Qlb9ttwqk/DS7yPxH8lyOQ1wv/LnbqL8CKRcPpeoGbPCt1lmZeYoINjCw\r\n"	\
"jry3/u1tGNFhnSWr3se66jHqwR3Qw0YS7WHDzMaSX+Ck/JMdSOLV2LOpv2n9kv6b\r\n"	\
"lQhhl2M5QrVve6xurR4/NL4PyVfAeficbukxLq3Zi3FK7JrsPiqW0Qk5lFZ9LTCd\r\n"	\
"hWz/t7fQeC7B0/oqyFLJGTo8sTUrDgpfqDVafqKTdRTPcOerErwbskTzu9CyKkpQ\r\n"	\
"YD4Cu5wptmM3AG0CRuobNlPIcNoPK8eLUfTrSObrng0/xp6AxVbftHxzR4aWgWti\r\n"	\
"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\r\n"	\
"-----END DILITHIUM PRIVATE KEY-----\r\n"	

#define TEST_SRV_CRT_DILITHIUM_SHAKE256_PEM \
"-----BEGIN CERTIFICATE-----\r\n"	\
"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\r\n"	\
"GgAAABoAAAAKAAAAfGgIABgRDwAY/Ol2\r\n"	\
"-----END CERTIFICATE-----\r\n"	


/*
 *
 * Test certificates and keys as C variables
 *
 */

/*
 * CA
 */
const char mbedtls_test_ca_crt_sphincs_shake256_pem[] = TEST_CA_CRT_SPHINCS_SHAKE256_PEM;
const char mbedtls_test_ca_crt_sphincs_sha256_pem[] = TEST_CA_CRT_SPHINCS_SHA256_PEM;

const char mbedtls_test_ca_crt_dilithium_shake256_pem[] = TEST_CA_CRT_DILITHIUM_SHAKE256_PEM;

const char mbedtls_test_ca_crt_ec_pem[]           = TEST_CA_CRT_EC_PEM;
const char mbedtls_test_ca_key_ec_pem[]           = TEST_CA_KEY_EC_PEM;
const char mbedtls_test_ca_pwd_ec_pem[]           = TEST_CA_PWD_EC_PEM;
const char mbedtls_test_ca_key_rsa_pem[]          = TEST_CA_KEY_RSA_PEM;
const char mbedtls_test_ca_pwd_rsa_pem[]          = TEST_CA_PWD_RSA_PEM;
const char mbedtls_test_ca_crt_rsa_sha1_pem[]     = TEST_CA_CRT_RSA_SHA1_PEM;
const char mbedtls_test_ca_crt_rsa_sha256_pem[]   = TEST_CA_CRT_RSA_SHA256_PEM;

const unsigned char mbedtls_test_ca_crt_ec_der[]   = TEST_CA_CRT_EC_DER;
const unsigned char mbedtls_test_ca_key_ec_der[]   = TEST_CA_KEY_EC_DER;
const unsigned char mbedtls_test_ca_key_rsa_der[]  = TEST_CA_KEY_RSA_DER;
const unsigned char mbedtls_test_ca_crt_rsa_sha1_der[]   =
    TEST_CA_CRT_RSA_SHA1_DER;
const unsigned char mbedtls_test_ca_crt_rsa_sha256_der[] =
    TEST_CA_CRT_RSA_SHA256_DER;

const size_t mbedtls_test_ca_crt_sphincs_shake256_pem_len =
    sizeof(mbedtls_test_ca_crt_sphincs_shake256_pem);
const size_t mbedtls_test_ca_crt_sphincs_sha256_pem_len =
    sizeof(mbedtls_test_ca_crt_sphincs_sha256_pem);
    
const size_t mbedtls_test_ca_crt_dilithium_shake256_pem_len =
    sizeof(mbedtls_test_ca_crt_dilithium_shake256_pem);

const size_t mbedtls_test_ca_crt_ec_pem_len =
    sizeof( mbedtls_test_ca_crt_ec_pem );
const size_t mbedtls_test_ca_key_ec_pem_len =
    sizeof( mbedtls_test_ca_key_ec_pem );
const size_t mbedtls_test_ca_pwd_ec_pem_len =
    sizeof( mbedtls_test_ca_pwd_ec_pem ) - 1;
const size_t mbedtls_test_ca_key_rsa_pem_len =
    sizeof( mbedtls_test_ca_key_rsa_pem );
const size_t mbedtls_test_ca_pwd_rsa_pem_len =
    sizeof( mbedtls_test_ca_pwd_rsa_pem ) - 1;
const size_t mbedtls_test_ca_crt_rsa_sha1_pem_len =
    sizeof( mbedtls_test_ca_crt_rsa_sha1_pem );
const size_t mbedtls_test_ca_crt_rsa_sha256_pem_len =
    sizeof( mbedtls_test_ca_crt_rsa_sha256_pem );

const size_t mbedtls_test_ca_crt_ec_der_len =
    sizeof( mbedtls_test_ca_crt_ec_der );
const size_t mbedtls_test_ca_key_ec_der_len =
    sizeof( mbedtls_test_ca_key_ec_der );
const size_t mbedtls_test_ca_pwd_ec_der_len = 0;
const size_t mbedtls_test_ca_key_rsa_der_len =
    sizeof( mbedtls_test_ca_key_rsa_der );
const size_t mbedtls_test_ca_pwd_rsa_der_len = 0;
const size_t mbedtls_test_ca_crt_rsa_sha1_der_len =
    sizeof( mbedtls_test_ca_crt_rsa_sha1_der );
const size_t mbedtls_test_ca_crt_rsa_sha256_der_len =
    sizeof( mbedtls_test_ca_crt_rsa_sha256_der );

/*
 * Server
 */

const char mbedtls_test_srv_crt_sphincs_shake256_pem[] = TEST_SRV_CRT_SPHINCS_SHAKE256_PEM;
const char mbedtls_test_srv_crt_sphincs_sha256_pem[] = TEST_SRV_CRT_SPHINCS_SHA256_PEM;
const char mbedtls_test_srv_key_sphincs_shake256_pem[] = TEST_SRV_KEY_SPHINCS_SHAKE256_PEM;
const char mbedtls_test_srv_key_sphincs_sha256_pem[] = TEST_SRV_KEY_SPHINCS_SHA256_PEM;

const char mbedtls_test_srv_crt_dilithium_shake256_pem[] = TEST_SRV_CRT_DILITHIUM_SHAKE256_PEM;
const char mbedtls_test_srv_key_dilithium_shake256_pem[] = TEST_SRV_KEY_DILITHIUM_SHAKE256_PEM;

const char mbedtls_test_srv_crt_ec_pem[]           = TEST_SRV_CRT_EC_PEM;
const char mbedtls_test_srv_key_ec_pem[]           = TEST_SRV_KEY_EC_PEM;
const char mbedtls_test_srv_pwd_ec_pem[]           = "";
const char mbedtls_test_srv_key_rsa_pem[]          = TEST_SRV_KEY_RSA_PEM;
const char mbedtls_test_srv_pwd_rsa_pem[]          = "";
const char mbedtls_test_srv_crt_rsa_sha1_pem[]     = TEST_SRV_CRT_RSA_SHA1_PEM;
const char mbedtls_test_srv_crt_rsa_sha256_pem[]   = TEST_SRV_CRT_RSA_SHA256_PEM;

const unsigned char mbedtls_test_srv_crt_ec_der[]   = TEST_SRV_CRT_EC_DER;
const unsigned char mbedtls_test_srv_key_ec_der[]   = TEST_SRV_KEY_EC_DER;
const unsigned char mbedtls_test_srv_key_rsa_der[]  = TEST_SRV_KEY_RSA_DER;
const unsigned char mbedtls_test_srv_crt_rsa_sha1_der[]   =
    TEST_SRV_CRT_RSA_SHA1_DER;
const unsigned char mbedtls_test_srv_crt_rsa_sha256_der[] =
    TEST_SRV_CRT_RSA_SHA256_DER;

const size_t mbedtls_test_srv_crt_sphincs_shake256_pem_len =
    sizeof(mbedtls_test_srv_crt_sphincs_shake256_pem);
const size_t mbedtls_test_srv_crt_sphincs_sha256_pem_len =
    sizeof(mbedtls_test_srv_crt_sphincs_sha256_pem);
const size_t mbedtls_test_srv_key_sphincs_shake256_pem_len =
    sizeof(mbedtls_test_srv_key_sphincs_shake256_pem);
const size_t mbedtls_test_srv_key_sphincs_sha256_pem_len =
    sizeof(mbedtls_test_srv_key_sphincs_sha256_pem);
    
const size_t mbedtls_test_srv_crt_dilithium_shake256_pem_len =
    sizeof(mbedtls_test_srv_crt_dilithium_shake256_pem);
const size_t mbedtls_test_srv_key_dilithium_shake256_pem_len =
    sizeof(mbedtls_test_srv_key_dilithium_shake256_pem);

const size_t mbedtls_test_srv_crt_ec_pem_len =
    sizeof( mbedtls_test_srv_crt_ec_pem );
const size_t mbedtls_test_srv_key_ec_pem_len =
    sizeof( mbedtls_test_srv_key_ec_pem );
const size_t mbedtls_test_srv_pwd_ec_pem_len =
    sizeof( mbedtls_test_srv_pwd_ec_pem ) - 1;
const size_t mbedtls_test_srv_key_rsa_pem_len =
    sizeof( mbedtls_test_srv_key_rsa_pem );
const size_t mbedtls_test_srv_pwd_rsa_pem_len =
    sizeof( mbedtls_test_srv_pwd_rsa_pem ) - 1;
const size_t mbedtls_test_srv_crt_rsa_sha1_pem_len =
    sizeof( mbedtls_test_srv_crt_rsa_sha1_pem );
const size_t mbedtls_test_srv_crt_rsa_sha256_pem_len =
    sizeof( mbedtls_test_srv_crt_rsa_sha256_pem );

const size_t mbedtls_test_srv_crt_ec_der_len =
    sizeof( mbedtls_test_srv_crt_ec_der );
const size_t mbedtls_test_srv_key_ec_der_len =
    sizeof( mbedtls_test_srv_key_ec_der );
const size_t mbedtls_test_srv_pwd_ec_der_len = 0;
const size_t mbedtls_test_srv_key_rsa_der_len =
    sizeof( mbedtls_test_srv_key_rsa_der );
const size_t mbedtls_test_srv_pwd_rsa_der_len = 0;
const size_t mbedtls_test_srv_crt_rsa_sha1_der_len =
    sizeof( mbedtls_test_srv_crt_rsa_sha1_der );
const size_t mbedtls_test_srv_crt_rsa_sha256_der_len =
    sizeof( mbedtls_test_srv_crt_rsa_sha256_der );

/*
 * Client
 */

const char mbedtls_test_cli_crt_ec_pem[]   = TEST_CLI_CRT_EC_PEM;
const char mbedtls_test_cli_key_ec_pem[]   = TEST_CLI_KEY_EC_PEM;
const char mbedtls_test_cli_pwd_ec_pem[]   = "";
const char mbedtls_test_cli_key_rsa_pem[]  = TEST_CLI_KEY_RSA_PEM;
const char mbedtls_test_cli_pwd_rsa_pem[]  = "";
const char mbedtls_test_cli_crt_rsa_pem[]  = TEST_CLI_CRT_RSA_PEM;

const unsigned char mbedtls_test_cli_crt_ec_der[]   = TEST_CLI_CRT_EC_DER;
const unsigned char mbedtls_test_cli_key_ec_der[]   = TEST_CLI_KEY_EC_DER;
const unsigned char mbedtls_test_cli_key_rsa_der[]  = TEST_CLI_KEY_RSA_DER;
const unsigned char mbedtls_test_cli_crt_rsa_der[]  = TEST_CLI_CRT_RSA_DER;

const size_t mbedtls_test_cli_crt_ec_pem_len =
    sizeof( mbedtls_test_cli_crt_ec_pem );
const size_t mbedtls_test_cli_key_ec_pem_len =
    sizeof( mbedtls_test_cli_key_ec_pem );
const size_t mbedtls_test_cli_pwd_ec_pem_len =
    sizeof( mbedtls_test_cli_pwd_ec_pem ) - 1;
const size_t mbedtls_test_cli_key_rsa_pem_len =
    sizeof( mbedtls_test_cli_key_rsa_pem );
const size_t mbedtls_test_cli_pwd_rsa_pem_len =
    sizeof( mbedtls_test_cli_pwd_rsa_pem ) - 1;
const size_t mbedtls_test_cli_crt_rsa_pem_len =
    sizeof( mbedtls_test_cli_crt_rsa_pem );

const size_t mbedtls_test_cli_crt_ec_der_len =
    sizeof( mbedtls_test_cli_crt_ec_der );
const size_t mbedtls_test_cli_key_ec_der_len =
    sizeof( mbedtls_test_cli_key_ec_der );
const size_t mbedtls_test_cli_key_rsa_der_len =
    sizeof( mbedtls_test_cli_key_rsa_der );
const size_t mbedtls_test_cli_crt_rsa_der_len =
    sizeof( mbedtls_test_cli_crt_rsa_der );

/*
 *
 * Definitions of test CRTs without specification of all parameters, choosing
 * them automatically according to the config. For example, mbedtls_test_ca_crt
 * is one of mbedtls_test_ca_crt_{rsa|ec}_{sha1|sha256}_{pem|der}.
 *
 */

/*
 * Dispatch between PEM and DER according to config
 */

#if defined(MBEDTLS_PEM_PARSE_C)

/* PEM encoded test CA certificates and keys */

#define TEST_CA_KEY_RSA                 TEST_CA_KEY_RSA_PEM
#define TEST_CA_PWD_RSA                 TEST_CA_PWD_RSA_PEM
#define TEST_CA_CRT_RSA_SHA256          TEST_CA_CRT_RSA_SHA256_PEM
#define TEST_CA_CRT_RSA_SHA1            TEST_CA_CRT_RSA_SHA1_PEM
#define TEST_CA_KEY_EC                  TEST_CA_KEY_EC_PEM
#define TEST_CA_PWD_EC                  TEST_CA_PWD_EC_PEM
#define TEST_CA_CRT_EC                  TEST_CA_CRT_EC_PEM
#define TEST_CA_CRT_SPHINCS_SHAKE256    TEST_CA_CRT_SPHINCS_SHAKE256_PEM
#define TEST_CA_CRT_SPHINCS_SHA256      TEST_CA_CRT_SPHINCS_SHA256_PEM
#define TEST_CA_CRT_DILITHIUM_SHAKE256  TEST_CA_CRT_DILITHIUM_SHAKE256_PEM

/* PEM encoded test server certificates and keys */

#define TEST_SRV_KEY_RSA        TEST_SRV_KEY_RSA_PEM
#define TEST_SRV_PWD_RSA        ""
#define TEST_SRV_CRT_RSA_SHA256 TEST_SRV_CRT_RSA_SHA256_PEM
#define TEST_SRV_CRT_RSA_SHA1   TEST_SRV_CRT_RSA_SHA1_PEM
#define TEST_SRV_KEY_EC         TEST_SRV_KEY_EC_PEM
#define TEST_SRV_PWD_EC         ""
#define TEST_SRV_CRT_EC         TEST_SRV_CRT_EC_PEM
#define TEST_SRV_CRT_SPHINCS_SHAKE256    TEST_SRV_CRT_SPHINCS_SHAKE256_PEM
#define TEST_SRV_CRT_SPHINCS_SHA256      TEST_SRV_CRT_SPHINCS_SHA256_PEM
#define TEST_SRV_KEY_SPHINCS_SHAKE256    TEST_SRV_KEY_SPHINCS_SHAKE256_PEM
#define TEST_SRV_KEY_SPHINCS_SHA256      TEST_SRV_KEY_SPHINCS_SHA256_PEM
#define TEST_SRV_CRT_DILITHIUM_SHAKE256    TEST_SRV_CRT_DILITHIUM_SHAKE256_PEM
#define TEST_SRV_KEY_DILITHIUM_SHAKE256    TEST_SRV_KEY_DILITHIUM_SHAKE256_PEM

/* PEM encoded test client certificates and keys */

#define TEST_CLI_KEY_RSA  TEST_CLI_KEY_RSA_PEM
#define TEST_CLI_PWD_RSA  ""
#define TEST_CLI_CRT_RSA  TEST_CLI_CRT_RSA_PEM
#define TEST_CLI_KEY_EC   TEST_CLI_KEY_EC_PEM
#define TEST_CLI_PWD_EC   ""
#define TEST_CLI_CRT_EC   TEST_CLI_CRT_EC_PEM


#else /* MBEDTLS_PEM_PARSE_C */

/* DER encoded test CA certificates and keys */

#define TEST_CA_KEY_RSA        TEST_CA_KEY_RSA_DER
#define TEST_CA_PWD_RSA        ""
#define TEST_CA_CRT_RSA_SHA256 TEST_CA_CRT_RSA_SHA256_DER
#define TEST_CA_CRT_RSA_SHA1   TEST_CA_CRT_RSA_SHA1_DER
#define TEST_CA_KEY_EC         TEST_CA_KEY_EC_DER
#define TEST_CA_PWD_EC         ""
#define TEST_CA_CRT_EC         TEST_CA_CRT_EC_DER
#define TEST_CA_CRT_SPHINCS_SHAKE256      ""
#define TEST_CA_CRT_SPHINCS_SHA256        ""
#define TEST_CA_CRT_DILITHIUM_SHAKE256    ""

/* DER encoded test server certificates and keys */

#define TEST_SRV_KEY_RSA        TEST_SRV_KEY_RSA_DER
#define TEST_SRV_PWD_RSA        ""
#define TEST_SRV_CRT_RSA_SHA256 TEST_SRV_CRT_RSA_SHA256_DER
#define TEST_SRV_CRT_RSA_SHA1   TEST_SRV_CRT_RSA_SHA1_DER
#define TEST_SRV_KEY_EC         TEST_SRV_KEY_EC_DER
#define TEST_SRV_PWD_EC         ""
#define TEST_SRV_CRT_EC         TEST_SRV_CRT_EC_DER
#define TEST_SRV_CRT_SPHINCS_SHAKE256      ""
#define TEST_SRV_CRT_SPHINCS_SHA256       ""
#define TEST_SRV_KEY_SPHINCS_SHAKE256     ""
#define TEST_SRV_KEY_SPHINCS_SHA256       ""
#define TEST_SRV_CRT_DILITHIUM_SHAKE256   ""
#define TEST_SRV_KEY_DILITHIUM_SHAKE256   ""

/* DER encoded test client certificates and keys */

#define TEST_CLI_KEY_RSA  TEST_CLI_KEY_RSA_DER
#define TEST_CLI_PWD_RSA  ""
#define TEST_CLI_CRT_RSA  TEST_CLI_CRT_RSA_DER
#define TEST_CLI_KEY_EC   TEST_CLI_KEY_EC_DER
#define TEST_CLI_PWD_EC   ""
#define TEST_CLI_CRT_EC   TEST_CLI_CRT_EC_DER

#endif /* MBEDTLS_PEM_PARSE_C */

const char mbedtls_test_ca_key_rsa[]         = TEST_CA_KEY_RSA;
const char mbedtls_test_ca_pwd_rsa[]         = TEST_CA_PWD_RSA;
const char mbedtls_test_ca_crt_rsa_sha256[]  = TEST_CA_CRT_RSA_SHA256;
const char mbedtls_test_ca_crt_rsa_sha1[]    = TEST_CA_CRT_RSA_SHA1;
const char mbedtls_test_ca_key_ec[]          = TEST_CA_KEY_EC;
const char mbedtls_test_ca_pwd_ec[]          = TEST_CA_PWD_EC;
const char mbedtls_test_ca_crt_ec[]          = TEST_CA_CRT_EC;
const char mbedtls_test_ca_crt_sphincs_shake256[] = TEST_CA_CRT_SPHINCS_SHAKE256;
const char mbedtls_test_ca_crt_sphincs_sha256[] = TEST_CA_CRT_SPHINCS_SHA256;
const char mbedtls_test_ca_crt_dilithium_shake256[] = TEST_CA_CRT_DILITHIUM_SHAKE256;

const char mbedtls_test_srv_key_rsa[]        = TEST_SRV_KEY_RSA;
const char mbedtls_test_srv_pwd_rsa[]        = TEST_SRV_PWD_RSA;
const char mbedtls_test_srv_crt_rsa_sha256[] = TEST_SRV_CRT_RSA_SHA256;
const char mbedtls_test_srv_crt_rsa_sha1[]   = TEST_SRV_CRT_RSA_SHA1;
const char mbedtls_test_srv_key_ec[]         = TEST_SRV_KEY_EC;
const char mbedtls_test_srv_pwd_ec[]         = TEST_SRV_PWD_EC;
const char mbedtls_test_srv_crt_ec[]         = TEST_SRV_CRT_EC;
const char mbedtls_test_srv_key_sphincs_shake256[] = TEST_SRV_KEY_SPHINCS_SHAKE256;
const char mbedtls_test_srv_key_sphincs_sha256[] = TEST_SRV_KEY_SPHINCS_SHA256;
const char mbedtls_test_srv_crt_sphincs_shake256[] = TEST_SRV_CRT_SPHINCS_SHAKE256;
const char mbedtls_test_srv_crt_sphincs_sha256[] = TEST_SRV_CRT_SPHINCS_SHA256;
const char mbedtls_test_srv_key_dilithium_shake256[] = TEST_SRV_KEY_DILITHIUM_SHAKE256;
const char mbedtls_test_srv_crt_dilithium_shake256[] = TEST_SRV_CRT_DILITHIUM_SHAKE256;

const char mbedtls_test_cli_key_rsa[]        = TEST_CLI_KEY_RSA;
const char mbedtls_test_cli_pwd_rsa[]        = TEST_CLI_PWD_RSA;
const char mbedtls_test_cli_crt_rsa[]        = TEST_CLI_CRT_RSA;
const char mbedtls_test_cli_key_ec[]         = TEST_CLI_KEY_EC;
const char mbedtls_test_cli_pwd_ec[]         = TEST_CLI_PWD_EC;
const char mbedtls_test_cli_crt_ec[]         = TEST_CLI_CRT_EC;

const size_t mbedtls_test_ca_crt_sphincs_shake256_len =
    sizeof(mbedtls_test_ca_crt_sphincs_shake256);
const size_t mbedtls_test_ca_crt_sphincs_sha256_len =
    sizeof(mbedtls_test_ca_crt_sphincs_sha256);
const size_t mbedtls_test_ca_crt_dilithium_shake256_len =
    sizeof(mbedtls_test_ca_crt_dilithium_shake256);
const size_t mbedtls_test_ca_key_rsa_len =
    sizeof( mbedtls_test_ca_key_rsa );
const size_t mbedtls_test_ca_pwd_rsa_len =
    sizeof( mbedtls_test_ca_pwd_rsa ) - 1;
const size_t mbedtls_test_ca_crt_rsa_sha256_len =
    sizeof( mbedtls_test_ca_crt_rsa_sha256 );
const size_t mbedtls_test_ca_crt_rsa_sha1_len =
    sizeof( mbedtls_test_ca_crt_rsa_sha1 );
const size_t mbedtls_test_ca_key_ec_len =
    sizeof( mbedtls_test_ca_key_ec );
const size_t mbedtls_test_ca_pwd_ec_len =
    sizeof( mbedtls_test_ca_pwd_ec ) - 1;
const size_t mbedtls_test_ca_crt_ec_len =
    sizeof( mbedtls_test_ca_crt_ec );

const size_t mbedtls_test_srv_crt_sphics_shake256_len =
    sizeof(mbedtls_test_srv_crt_sphincs_shake256);
const size_t mbedtls_test_srv_crt_sphincs_sha256_len =
    sizeof(mbedtls_test_srv_crt_sphincs_sha256);
const size_t mbedtls_test_srv_key_sphincs_shake256_len =
    sizeof(mbedtls_test_srv_key_sphincs_shake256);
const size_t mbedtls_test_srv_key_sphincs_sha256_len =
    sizeof(mbedtls_test_srv_key_sphincs_sha256);
const size_t mbedtls_test_srv_crt_dilithium_shake256_len =
    sizeof(mbedtls_test_srv_crt_dilithium_shake256);
const size_t mbedtls_test_srv_key_dilithium_shake256_len =
    sizeof(mbedtls_test_srv_key_dilithium_shake256);
const size_t mbedtls_test_srv_key_rsa_len =
    sizeof( mbedtls_test_srv_key_rsa );
const size_t mbedtls_test_srv_pwd_rsa_len =
    sizeof( mbedtls_test_srv_pwd_rsa ) -1;
const size_t mbedtls_test_srv_crt_rsa_sha256_len =
    sizeof( mbedtls_test_srv_crt_rsa_sha256 );
const size_t mbedtls_test_srv_crt_rsa_sha1_len =
    sizeof( mbedtls_test_srv_crt_rsa_sha1 );
const size_t mbedtls_test_srv_key_ec_len =
    sizeof( mbedtls_test_srv_key_ec );
const size_t mbedtls_test_srv_pwd_ec_len =
    sizeof( mbedtls_test_srv_pwd_ec ) - 1;
const size_t mbedtls_test_srv_crt_ec_len =
    sizeof( mbedtls_test_srv_crt_ec );

const size_t mbedtls_test_cli_key_rsa_len =
    sizeof( mbedtls_test_cli_key_rsa );
const size_t mbedtls_test_cli_pwd_rsa_len =
    sizeof( mbedtls_test_cli_pwd_rsa ) - 1;
const size_t mbedtls_test_cli_crt_rsa_len =
    sizeof( mbedtls_test_cli_crt_rsa );
const size_t mbedtls_test_cli_key_ec_len =
    sizeof( mbedtls_test_cli_key_ec );
const size_t mbedtls_test_cli_pwd_ec_len =
    sizeof( mbedtls_test_cli_pwd_ec ) - 1;
const size_t mbedtls_test_cli_crt_ec_len =
    sizeof( mbedtls_test_cli_crt_ec );

/*
 * Dispatch between SHAKE256 and SHA-256 for SPHINCS+
 */
#define MBEDTLS_TEST_SHAKE256
#if defined(MBEDTLS_TEST_SHAKE256)
#define TEST_CA_CRT_SPHINCS  TEST_CA_CRT_SPHINCS_SHAKE256
#define TEST_SRV_CRT_SPHINCS TEST_SRV_CRT_SPHINCS_SHAKE256
#define TEST_SRV_KEY_SPHINCS TEST_SRV_KEY_SPHINCS_SHAKE256
#else
#define TEST_CA_CRT_SPHINCS  TEST_CA_CRT_SPHINCS_SHA256
#define TEST_SRV_CRT_SPHINCS TEST_SRV_CRT_SPHINCS_SHA256
#define TEST_SRV_KEY_SPHINCS TEST_SRV_KEY_SPHINCS_SHA256
#endif // defined(MBEDTLS_TEST_SHAKE256)


#if defined(MBEDTLS_TEST_SHAKE256)
#define TEST_CA_CRT_DILITHIUM  TEST_CA_CRT_DILITHIUM_SHAKE256
#define TEST_SRV_CRT_DILITHIUM TEST_SRV_CRT_DILITHIUM_SHAKE256
#define TEST_SRV_KEY_DILITHIUM TEST_SRV_KEY_DILITHIUM_SHAKE256
#endif // defined(MBEDTLS_TEST_SHAKE256)

/*
 * Dispatch between SHA-1 and SHA-256
 */
#if defined(MBEDTLS_SHA256_C)
#define TEST_CA_CRT_RSA  TEST_CA_CRT_RSA_SHA256
#define TEST_SRV_CRT_RSA TEST_SRV_CRT_RSA_SHA256
#else
#define TEST_CA_CRT_RSA  TEST_CA_CRT_RSA_SHA1
#define TEST_SRV_CRT_RSA TEST_SRV_CRT_RSA_SHA1
#endif /* MBEDTLS_SHA256_C */

const char mbedtls_test_ca_crt_rsa[]  = TEST_CA_CRT_RSA;
const char mbedtls_test_srv_crt_rsa[] = TEST_SRV_CRT_RSA;

const size_t mbedtls_test_ca_crt_rsa_len =
    sizeof( mbedtls_test_ca_crt_rsa );
const size_t mbedtls_test_srv_crt_rsa_len =
    sizeof( mbedtls_test_srv_crt_rsa );

/*
 * Dispatch between RSA and EC
 */

#if defined(MBEDTLS_SPHINCS_C)

#define TEST_CA_KEY ""
#define TEST_CA_PWD ""
#define TEST_CA_CRT TEST_CA_CRT_SPHINCS

#define TEST_SRV_KEY TEST_SRV_KEY_SPHINCS
#define TEST_SRV_PWD ""
#define TEST_SRV_CRT TEST_SRV_CRT_SPHINCS

#define TEST_CLI_KEY ""
#define TEST_CLI_PWD ""
#define TEST_CLI_CRT ""

#elif defined(MBEDTLS_DILITHIUM_C)

#define TEST_CA_KEY ""
#define TEST_CA_PWD ""
#define TEST_CA_CRT TEST_CA_CRT_DILITHIUM

#define TEST_SRV_KEY TEST_SRV_KEY_DILITHIUM
#define TEST_SRV_PWD ""
#define TEST_SRV_CRT TEST_SRV_CRT_DILITHIUM

#define TEST_CLI_KEY ""
#define TEST_CLI_PWD ""
#define TEST_CLI_CRT ""

#elif defined(MBEDTLS_RSA_C)

#define TEST_CA_KEY TEST_CA_KEY_RSA
#define TEST_CA_PWD TEST_CA_PWD_RSA
#define TEST_CA_CRT TEST_CA_CRT_RSA

#define TEST_SRV_KEY TEST_SRV_KEY_RSA
#define TEST_SRV_PWD TEST_SRV_PWD_RSA
#define TEST_SRV_CRT TEST_SRV_CRT_RSA

#define TEST_CLI_KEY TEST_CLI_KEY_RSA
#define TEST_CLI_PWD TEST_CLI_PWD_RSA
#define TEST_CLI_CRT TEST_CLI_CRT_RSA

#else /* no RSA, so assume ECDSA */

#define TEST_CA_KEY TEST_CA_KEY_EC
#define TEST_CA_PWD TEST_CA_PWD_EC
#define TEST_CA_CRT TEST_CA_CRT_EC

#define TEST_SRV_KEY TEST_SRV_KEY_EC
#define TEST_SRV_PWD TEST_SRV_PWD_EC
#define TEST_SRV_CRT TEST_SRV_CRT_EC

#define TEST_CLI_KEY TEST_CLI_KEY_EC
#define TEST_CLI_PWD TEST_CLI_PWD_EC
#define TEST_CLI_CRT TEST_CLI_CRT_EC

#endif /* MBEDTLS_RSA_C */

/* API stability forces us to declare
 *   mbedtls_test_{ca|srv|cli}_{key|pwd|crt}
 * as pointers. */
static const char test_ca_key[] = TEST_CA_KEY;
static const char test_ca_pwd[] = TEST_CA_PWD;
static const char test_ca_crt[] = TEST_CA_CRT;

static const char test_srv_key[] = TEST_SRV_KEY;
static const char test_srv_pwd[] = TEST_SRV_PWD;
static const char test_srv_crt[] = TEST_SRV_CRT;

static const char test_cli_key[] = TEST_CLI_KEY;
static const char test_cli_pwd[] = TEST_CLI_PWD;
static const char test_cli_crt[] = TEST_CLI_CRT;

const char *mbedtls_test_ca_key = test_ca_key;
const char *mbedtls_test_ca_pwd = test_ca_pwd;
const char *mbedtls_test_ca_crt = test_ca_crt;

const char *mbedtls_test_srv_key = test_srv_key;
const char *mbedtls_test_srv_pwd = test_srv_pwd;
const char *mbedtls_test_srv_crt = test_srv_crt;

const char *mbedtls_test_cli_key = test_cli_key;
const char *mbedtls_test_cli_pwd = test_cli_pwd;
const char *mbedtls_test_cli_crt = test_cli_crt;

const size_t mbedtls_test_ca_key_len =
    sizeof( test_ca_key );
const size_t mbedtls_test_ca_pwd_len =
    sizeof( test_ca_pwd ) - 1;
const size_t mbedtls_test_ca_crt_len =
    sizeof( test_ca_crt );

const size_t mbedtls_test_srv_key_len =
    sizeof( test_srv_key );
const size_t mbedtls_test_srv_pwd_len =
    sizeof( test_srv_pwd ) - 1;
const size_t mbedtls_test_srv_crt_len =
    sizeof( test_srv_crt );

const size_t mbedtls_test_cli_key_len =
    sizeof( test_cli_key );
const size_t mbedtls_test_cli_pwd_len =
    sizeof( test_cli_pwd ) - 1;
const size_t mbedtls_test_cli_crt_len =
    sizeof( test_cli_crt );

/*
 *
 * Lists of certificates
 *
 */

/* List of CAs in PEM or DER, depending on config */
const char * mbedtls_test_cas[] = {
#if defined(MBEDTLS_SPHINCS_C)
#if defined(MBEDTLS_TEST_SHAKE256)
    mbedtls_test_ca_crt_sphincs_shake256,
#else
    mbedtls_test_ca_crt_sphincs_sha256,
#endif
#endif /*MBEDTLS_SPHINCS_C*/
#if defined(MBEDTLS_DILITHIUM_C)
    mbedtls_test_ca_crt_dilithium_shake256,
#endif /*MBEDTLS_DILITHIUM_C*/
#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_SHA1_C)
    mbedtls_test_ca_crt_rsa_sha1,
#endif
#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_SHA256_C)
    mbedtls_test_ca_crt_rsa_sha256,
#endif
#if defined(MBEDTLS_ECDSA_C)
    mbedtls_test_ca_crt_ec,
#endif
    NULL
};
const size_t mbedtls_test_cas_len[] = {
#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_SHA1_C)
    sizeof( mbedtls_test_ca_crt_rsa_sha1 ),
#endif
#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_SHA256_C)
    sizeof( mbedtls_test_ca_crt_rsa_sha256 ),
#endif
#if defined(MBEDTLS_ECDSA_C)
    sizeof( mbedtls_test_ca_crt_ec ),
#endif
    0
};

/* List of all available CA certificates in DER format */
const unsigned char * mbedtls_test_cas_der[] = {
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_SHA256_C)
    mbedtls_test_ca_crt_rsa_sha256_der,
#endif /* MBEDTLS_SHA256_C */
#if defined(MBEDTLS_SHA1_C)
    mbedtls_test_ca_crt_rsa_sha1_der,
#endif /* MBEDTLS_SHA1_C */
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECDSA_C)
    mbedtls_test_ca_crt_ec_der,
#endif /* MBEDTLS_ECDSA_C */
    NULL
};

const size_t mbedtls_test_cas_der_len[] = {
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_SHA256_C)
    sizeof( mbedtls_test_ca_crt_rsa_sha256_der ),
#endif /* MBEDTLS_SHA256_C */
#if defined(MBEDTLS_SHA1_C)
    sizeof( mbedtls_test_ca_crt_rsa_sha1_der ),
#endif /* MBEDTLS_SHA1_C */
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECDSA_C)
    sizeof( mbedtls_test_ca_crt_ec_der ),
#endif /* MBEDTLS_ECDSA_C */
    0
};

/* Concatenation of all available CA certificates in PEM format */
#if defined(MBEDTLS_PEM_PARSE_C)
const char mbedtls_test_cas_pem[] =
#if defined(MBEDTLS_SPHINCS_C)
#if defined(MBEDTLS_TEST_SHAKE256)
    TEST_CA_CRT_SPHINCS_SHAKE256_PEM
#else
    TEST_CA_CRT_SPHINCS_SHA256_PEM
#endif // defined(MBEDTLS_TEST_SHAKE256)
#endif // defined(MBEDTLS_SPHINCS_C)
#if defined(MBEDTLS_DILITHIUM_C)
    TEST_CA_CRT_DILITHIUM_SHAKE256_PEM
#endif // defined(MBEDTLS_DILITHIUM_C)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_SHA256_C)
    TEST_CA_CRT_RSA_SHA256_PEM
#endif /* MBEDTLS_SHA256_C */
#if defined(MBEDTLS_SHA1_C)
    TEST_CA_CRT_RSA_SHA1_PEM
#endif /* MBEDTLS_SHA1_C */
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECDSA_C)
    TEST_CA_CRT_EC_PEM
#endif /* MBEDTLS_ECDSA_C */
    "";
const size_t mbedtls_test_cas_pem_len = sizeof( mbedtls_test_cas_pem );
#endif /* MBEDTLS_PEM_PARSE_C */

#endif /* MBEDTLS_CERTS_C */
