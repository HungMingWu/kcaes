/*
 * Copyright (C) 2017, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include <stdio.h>
#include "kcaes.h"

int main(int argc, char *argv[])
{
        struct kcaes_handle *handle;

        int ret = kcaes_cipher_init(&handle, "cbc(aes)");
        if (ret) {
                return ret;
	}

	unsigned char key[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
	unsigned char iv[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
	unsigned char input[64], output[64];
	for (size_t i = 0; i < 64; i++)
		input[i] = i;
        ret = kcaes_cipher_setkey(handle, key, 16);
        if (ret) {
                return ret;
	}
	printf("iv size = %d\n", kcaes_cipher_ivsize(handle));
	printf("block size = %d\n", kcaes_cipher_blocksize(handle));
        ret = kcaes_cipher_decrypt(handle, input, 64, iv, output, 64, KCAES_ACCESS_HEURISTIC);
        if (ret < 0) {
                return ret;
	}
	for (size_t i = 0; i < 4; i++) {
		for (size_t j = 0; j < 16; j++)
			printf("%d ", output[i * 16 + j]);
		printf("\n");
	}
	printf("\n");
        kcaes_cipher_destroy(handle);
	return 0;
}
