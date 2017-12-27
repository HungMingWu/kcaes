#ifndef KCAES_H
#define KCAES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Flags for the encrypt / decrypt operations
 * 
 * @KCAES_ACCESS_HEURISTIC Allow the libkcaes heuristic to determine the
 * optimal kernel access type
 * @KCAES_ACCESS_VMSPLICE Require libkcaes to always use the vmsplice zero
 * copy kernel interface
 * @KCAES_ACCESS_SENDMSG Require libkcaes to always use the sendmsg kernel
 * interface
 */
#define KCAES_ACCESS_HEURISTIC 	0x0
#define KCAES_ACCESS_VMSPLICE  	0x1
#define KCAES_ACCESS_SENDMSG   	0x2

/*
 * Opaque cipher handle
 */
struct kcaes_handle;

/**
 * DOC: Symmetric Cipher API
 *
 * API function calls used to invoke symmetric ciphers.
 */

/*
 * kcaes_cipher_init() - initialize cipher handle
 *
 * @handle: [out] cipher handle filled during the call
 * @ciphername: [in] kernel crypto API cipher name as specified in
 *	       /proc/crypto
 * @flags: [in] flags specifying the type of cipher handle
 *
 * This function provides the initialization of a symmetric cipher handle and
 * establishes the connection to the kernel.
 *
 * On success, a pointer to kcaes_handle object is returned in *handle.
 * Function kcaes_cipher_destroy should be called afterwards to free resources.
 *
 * @return 0 upon success;
 *	   -ENOENT - algorithm not available;
 *	   -EOPNOTSUPP - AF_ALG family not available;
 *	   -EINVAL - accept syscall failed
 *	   -ENOMEM - cipher handle cannot be allocated
 */
int kcaes_cipher_init(struct kcaes_handle **handle, const char *ciphername);

/**
 * kcaes_cipher_destroy() - close the cipher handle and release resources
 *
 * @handle: [in] cipher handle to release
 */
void kcaes_cipher_destroy(struct kcaes_handle *handle);

/**
 * kcaes_cipher_setkey() - set the key for the cipher handle
 *
 * @handle: [in] cipher handle
 * @key: [in] key buffer
 * @keylen: [in] length of key buffer
 *
 * With this function, the caller sets the key for subsequent encryption or
 * decryption operations.
 *
 * After the caller provided the key, the caller may securely destroy the key
 * as it is now maintained by the kernel.
 *
 * @return 0 upon success (in case of an akcipher handle, a positive integer
 *	   is returned that denominates the maximum output size of the
 *	   cryptographic operation -- this value must be used as the size
 *	   of the output buffer for one cryptographic operation);
 *	   a negative errno-style error code if an error occurred
 */
int kcaes_cipher_setkey(struct kcaes_handle *handle,
			const uint8_t *key, uint32_t keylen);

/**
 * kcaes_cipher_encrypt() - encrypt data (synchronous one shot)
 *
 * @handle: [in] cipher handle
 * @in: [in] plaintext data buffer
 * @inlen: [in] length of in buffer
 * @iv: [in] IV to be used for cipher operation
 * @out: [out] ciphertext data buffer
 * @outlen: [in] length of out buffer
 * @access: [in] kernel access type (KCAES_ACCESS_HEURISTIC - use internal
 *	    heuristic for  fastest kernel access; KCAES_ACCESS_VMSPLICE - use
 *	    vmsplice access; KCAES_ACCESS_SENDMSG - sendmsg access)
 *
 * It is perfectly legal to use the same buffer as the plaintext and
 * ciphertext pointers. That would mean that after the encryption operation,
 * the plaintext is overwritten with the ciphertext.
 *
 * The memory should be aligned at the page boundary using
 * posix_memalign(sysconf(_SC_PAGESIZE)), If it is not aligned at the page
 * boundary, the vmsplice call may not send all data to the kernel.
 *
 * The IV buffer must be exactly kcaes_cipher_ivsize() bytes in size.
 *
 * @return number of bytes encrypted upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcaes_cipher_encrypt(struct kcaes_handle *handle,
			     const uint8_t *in, uint32_t inlen,
			     const uint8_t *iv,
			     uint8_t *out, uint32_t outlen, int access);

/**
 * kcaes_cipher_decrypt() - decrypt data (synchronous one shot)
 *
 * @handle: [in] cipher handle
 * @in: [in] ciphertext data buffer
 * @inlen: [in] length of in buffer
 * @iv: [in] IV to be used for cipher operation
 * @out: [out] plaintext data buffer
 * @outlen: [in] length of out bufferS
 * @access: [in] kernel access type (KCAES_ACCESS_HEURISTIC - use internal
 *	heuristic for  fastest kernel access; KCAES_ACCESS_VMSPLICE - use
 *	vmsplice access; KCAES_ACCESS_SENDMSG - sendmsg access)
 *
 * It is perfectly legal to use the same buffer as the plaintext and
 * ciphertext pointers. That would mean that after the encryption operation,
 * the ciphertext is overwritten with the plaintext.
 *
 * The memory should be aligned at the page boundary using
 * posix_memalign(sysconf(_SC_PAGESIZE)), If it is not aligned at the page
 * boundary, the vmsplice call may not send all data to the kernel.
 *
 * The IV buffer must be exactly kcaes_cipher_ivsize() bytes in size.
 *
 * @return number of bytes decrypted upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcaes_cipher_decrypt(struct kcaes_handle *handle,
			     const uint8_t *in, uint32_t inlen,
			     const uint8_t *iv,
			     uint8_t *out, uint32_t outlen, int access);

/**
 * kcaes_cipher_ivsize() - return size of IV required for cipher
 *
 * @handle: [in] cipher handle
 *
 * @return > 0 specifying the IV size;
 *	   0 on error
 */
uint32_t kcaes_cipher_ivsize(struct kcaes_handle *handle);

/**
 * kcaes_cipher_blocksize() - return size of one block of the cipher
 *
 * @handle: [in] cipher handle
 *
 * @return > 0 specifying the block size;
 *	   0 on error
 */
uint32_t kcaes_cipher_blocksize(struct kcaes_handle *handle);

#ifdef __cplusplus
}
#endif

#endif /* KCAES_H */
