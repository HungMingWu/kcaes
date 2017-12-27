#define _GNU_SOURCE
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <linux/rtnetlink.h>
#include <linux/if_alg.h>

#include "cryptouser.h"
#include "kcaes.h"

/* remove once in socket.h */
#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

/* make sure that is equal to include/crypto/if_alg.h */
#ifndef ALG_MAX_PAGES
#define ALG_MAX_PAGES 16
#endif

/*
 * Information obtained for different ciphers during handle init time
 * using the NETLINK_CRYPTO interface.
 * @blocksize block size of cipher (hash, symmetric, AEAD)
 * @ivsize size of IV of cipher (symmetric, AEAD)
 * @hash_digestsize size of message digest (hash)
 * @blk_min_keysize minimum key size (symmetric)
 * @blk_max_keysize maximum key size (symmetric)
 * @aead_maxauthsize maximum authentication tag size (AEAD)
 * @rng_seedsize seed size (RNG)
 */
struct kcaes_cipher_info {
	/* generic */
	uint32_t blocksize;
	uint32_t ivsize;
	/* hash */
	uint32_t hash_digestsize;
	/* blkcipher */
	uint32_t blk_min_keysize;
	uint32_t blk_max_keysize;
	/* aead */
	uint32_t aead_maxauthsize;
	/* rng */
	uint32_t rng_seedsize;
};

/*
 * Common data required for symmetric and AEAD ciphers
 * @iv: IV with length of kcaes_cipher_info->ivsize - input
 */
struct kcaes_cipher_data {
	const uint8_t *iv;
};

/*
 * AEAD data
 * @datalen: Length of plaintext / ciphertext data - input
 * @data: Pointer to plaintext / ciphertext data - input / output (the length is
 *        calculated with: kcaes_skcipher_data->inlen -
 *                         kcaes_aead_data->taglen - kcaes_aead_data->assoclen)
 * @assoclen: Length of associated data - input
 * @assoc: Pointer to associated data - input
 * @taglen: Length of authentication tag - input
 * @tag: Authentication tag - input for decryption, output for encryption
 * @retlen: internal data -- number plaintext / ciphertext bytes returned by
 *          the read system call
 */
struct kcaes_aead_data {
	uint32_t datalen;
	uint32_t assoclen;
	uint32_t taglen;
	uint8_t *data;
	uint8_t *assoc;
	uint8_t *tag;
};

struct kcaes_flags {
	/*
	 * New AEAD interface introduced with 4.9.0 to only require a tag
	 * if it is required as input or output.
	 */
	bool newtag;

	/* AF_ALG interfaces changed to process more pages concurrently. */
	uint32_t alg_max_pages;
};

struct kcaes_sys {
	unsigned long kernel_maj, kernel_minor, kernel_patchlevel;
};

/*
 * Cipher handle
 * @tfmfd: Socket descriptor for AF_ALG
 * @opfd: FD to open kernel crypto API TFM
 * @pipes: vmplice/splice pipe pair
 * @processed_sg: number of scatter/gather entries sent to the kernel
 * @ciper: Common data for all ciphers
 * @aead: AEAD cipher specific data
 * @info: properties of ciphers
 */
struct kcaes_handle {
	int tfmfd;
	int pipes[2];
	int opfd;
	uint32_t processed_sg;
	struct kcaes_sys sysinfo;
	struct kcaes_cipher_data cipher;
	struct kcaes_aead_data aead;
	struct kcaes_cipher_info info;
	struct kcaes_flags flags;
};

/************************************************************
 * Common helper used within the lib and as an API
 ************************************************************/
static void kcaes_memset_secure(void *s, int c, uint32_t n)
{
	memset(s, c, n);
	__asm__ __volatile__("" : : "r" (s) : "memory");
}

/************************************************************
 * Internal logic
 ************************************************************/

static int _kcaes_common_accept(struct kcaes_handle *handle, int *fdptr)
{
	int fd;

	if (*fdptr != -1)
		return 0;

	fd = accept(handle->tfmfd, NULL, 0);
	if (fd == -1) {
		int errsv;

		errsv = errno;
		return -errsv;
	}

	*fdptr = fd;

	return 0;
}

static int32_t _kcaes_common_send_meta_fd(struct kcaes_handle *handle, int *fdptr,
		struct iovec *iov, uint32_t iovlen,
		uint32_t enc, uint32_t flags)
{
	int32_t ret;
	char buffer_static[80] = { 0 };
	char *buffer_p = buffer_static;
	char *buffer_alloc = NULL;

	/* plaintext / ciphertext data */
	struct cmsghdr *header = NULL;
	uint32_t *type = NULL;
	struct msghdr msg;

	/* IV data */
	struct af_alg_iv *alg_iv = NULL;
	uint32_t iv_msg_size = handle->cipher.iv ?
		CMSG_SPACE(sizeof(*alg_iv) + handle->info.ivsize) :
		0;

	/* AEAD data */
	uint32_t *assoclen = NULL;
	uint32_t assoc_msg_size = handle->aead.assoclen ?
		CMSG_SPACE(sizeof(*assoclen)) : 0;

	uint32_t bufferlen =
		CMSG_SPACE(sizeof(*type)) + 	/* Encryption / Decryption */
		iv_msg_size +			/* IV */
		assoc_msg_size;			/* AEAD associated data size */

	ret = _kcaes_common_accept(handle, fdptr);
	if (ret)
		return ret;

	memset(&msg, 0, sizeof(msg));

	/* allocate buffer, if static buffer is too small */
	if (bufferlen > sizeof(buffer_static)) {
		buffer_alloc = calloc(1, bufferlen);
		if (!buffer_alloc)
			return -ENOMEM;
		buffer_p = buffer_alloc;
	}

	msg.msg_control = buffer_p;
	msg.msg_controllen = bufferlen;
	msg.msg_iov = iov;
	msg.msg_iovlen = iovlen;

	/* encrypt/decrypt operation */
	header = CMSG_FIRSTHDR(&msg);
	if (!header) {
		ret = -EFAULT;
		goto out;
	}
	header->cmsg_level = SOL_ALG;
	header->cmsg_type = ALG_SET_OP;
	header->cmsg_len = CMSG_LEN(sizeof(*type));
	type = (void*)CMSG_DATA(header);
	*type = enc;

	/* set IV */
	if (handle->cipher.iv) {
		header = CMSG_NXTHDR(&msg, header);
		if (!header) {
			ret = -EFAULT;
			goto out;
		}
		header->cmsg_level = SOL_ALG;
		header->cmsg_type = ALG_SET_IV;
		header->cmsg_len = iv_msg_size;
		alg_iv = (void*)CMSG_DATA(header);
		alg_iv->ivlen = handle->info.ivsize;
		memcpy(alg_iv->iv, handle->cipher.iv, handle->info.ivsize);
	}

	/* set AEAD information */
	if (handle->aead.assoclen) {
		/* Set associated data length */
		header = CMSG_NXTHDR(&msg, header);
		if (!header) {
			ret = -EFAULT;
			goto out;
		}
		header->cmsg_level = SOL_ALG;
		header->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
		header->cmsg_len = CMSG_LEN(sizeof(*assoclen));
		assoclen = (void*)CMSG_DATA(header);
		*assoclen = handle->aead.assoclen;
	}

	ret = sendmsg(*fdptr, &msg, flags);
	if (ret < 0)
		ret = -errno;

out:
	kcaes_memset_secure(buffer_p, 0, bufferlen);
	if (buffer_alloc)
		free(buffer_alloc);
	return ret;
}

static int32_t _kcaes_common_send_data_fd(struct kcaes_handle *handle, int *fdptr,
		struct iovec *iov, uint32_t iovlen,
		uint32_t flags)
{
	struct msghdr msg;
	int32_t ret;

	ret = _kcaes_common_accept(handle, fdptr);
	if (ret)
		return ret;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = iovlen;

	ret = sendmsg(*fdptr, &msg, flags);
	if (ret < 0)
		ret = -errno;

	return ret;
}

static int32_t _kcaes_common_vmsplice_chunk_fd(struct kcaes_handle *handle, int *fdptr,
		const uint8_t *in, uint32_t inlen,
		uint32_t flags)
{
	struct iovec iov;
	uint32_t processed = 0;
	int32_t ret = 0;
	uint32_t sflags = (flags & SPLICE_F_MORE) ? MSG_MORE : 0;

	if (inlen > INT_MAX)
		return -EMSGSIZE;

	if (!inlen)
		return _kcaes_common_send_data_fd(handle, &handle->opfd, NULL, 0, sflags);

	ret = _kcaes_common_accept(handle, fdptr);
	if (ret)
		return ret;

	while (inlen) {
		iov.iov_base = (void*)(uintptr_t)(in + processed);
		iov.iov_len = inlen;

		if ((handle->processed_sg++) > handle->flags.alg_max_pages) {
			ret = _kcaes_common_send_data_fd(handle, &handle->opfd, &iov, 1, sflags);
			if (ret < 0)
				return ret;
		} else {
			ret = vmsplice(handle->pipes[1], &iov, 1,
					SPLICE_F_GIFT|flags);
			if (ret < 0) {
				ret = -errno;
				return ret;
			}

			ret = splice(handle->pipes[0], NULL, *fdptr, NULL, ret,
					flags);
			if (ret < 0) {
				ret = -errno;
				return ret;
			}
		}

		processed += ret;
		inlen -= ret;
	}

	return processed;
}

static int32_t _kcaes_common_read_data_fd(struct kcaes_handle *handle, int *fdptr,
		uint8_t *out, uint32_t outlen)
{
	int32_t ret;

	if (outlen > INT_MAX)
		return -EMSGSIZE;

	ret = _kcaes_common_accept(handle, fdptr);
	if (ret)
		return ret;

	ret = read(*fdptr, out, outlen);
	if (ret < 0)
		ret = -errno;

	return ret;
}

static int _kcaes_common_setkey(struct kcaes_handle *handle,
		const uint8_t *key, uint32_t keylen)
{
	int ret;

	ret = setsockopt(handle->tfmfd, SOL_ALG, ALG_SET_KEY, key, keylen);
	if (ret < 0)
		ret = -errno;

	return ret;
}

static int __kcaes_common_getinfo(struct kcaes_handle *handle,
		const char *ciphername,
		int drivername)
{
	int ret = -EFAULT;

	/* NETLINK_CRYPTO specific */
	char buf[4096];
	struct nlmsghdr *res_n = (struct nlmsghdr *)buf;
	struct {
		struct nlmsghdr n;
		struct crypto_user_alg cru;
	} req;
	struct crypto_user_alg *cru_res = NULL;
	int res_len = 0;
	struct rtattr *tb[CRYPTOCFGA_MAX+1];
	struct rtattr *rta;

	/* AF_NETLINK specific */
	struct sockaddr_nl nl;
	int sd = 0;
	socklen_t addr_len;
	struct iovec iov;
	struct msghdr msg;

	memset(&req, 0, sizeof(req));
	memset(&buf, 0, sizeof(buf));
	memset(&msg, 0, sizeof(msg));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.cru));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = CRYPTO_MSG_GETALG;
	req.n.nlmsg_seq = time(NULL);

	if (drivername)
		strncpy(req.cru.cru_driver_name, ciphername,
				strlen(ciphername));
	else
		strncpy(req.cru.cru_name, ciphername, strlen(ciphername));

	/* talk to netlink socket */
	sd =  socket(AF_NETLINK, SOCK_RAW, NETLINK_CRYPTO);
	if (sd < 0) {
		return -errno;
	}
	memset(&nl, 0, sizeof(nl));
	nl.nl_family = AF_NETLINK;
	if (bind(sd, (struct sockaddr*)&nl, sizeof(nl)) < 0) {
		ret = -errno;
		goto out;
	}
	/* sanity check that netlink socket was successfully opened */
	addr_len = sizeof(nl);
	if (getsockname(sd, (struct sockaddr*)&nl, &addr_len) < 0) {
		ret = -errno;
		goto out;
	}
	if (addr_len != sizeof(nl)) {
		ret = -errno;
		goto out;
	}
	if (nl.nl_family != AF_NETLINK) {
		ret = -errno;
		goto out;
	}

	/* sending data */
	memset(&nl, 0, sizeof(nl));
	nl.nl_family = AF_NETLINK;
	iov.iov_base = (void*) &req.n;
	iov.iov_len = req.n.nlmsg_len;
	msg.msg_name = &nl;
	msg.msg_namelen = sizeof(nl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (sendmsg(sd, &msg, 0) < 0) {
		ret = -errno;
		goto out;
	}
	memset(buf,0,sizeof(buf));
	iov.iov_base = buf;
	while (1) {
		iov.iov_len = sizeof(buf);
		ret = recvmsg(sd, &msg, 0);
		if (ret < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			ret = -errno;
			goto out;
		}
		if (ret == 0) {
			ret = -errno;
			goto out;
		}
		if ((uint32_t)ret > sizeof(buf)) {
			ret = -errno;
			goto out;
		}
		break;
	}

	ret = -EFAULT;
	res_len = res_n->nlmsg_len;
	if (res_n->nlmsg_type == NLMSG_ERROR) {
		/*
		 * return -EAGAIN -- this error will occur if we received a
		 * driver name, but used it for a generic name. Allow caller
		 * to invoke function again where driver name is looked up
		 */
		ret = -EAGAIN;
		goto out;
	}

	if (res_n->nlmsg_type == CRYPTO_MSG_GETALG) {
		cru_res = NLMSG_DATA(res_n);
		res_len -= NLMSG_SPACE(sizeof(*cru_res));
	}
	if (res_len < 0) {
		goto out;
	}

	/* parse data */
	if (!cru_res) {
		ret = -EFAULT;
		goto out;
	}
	rta = CR_RTA(cru_res);
	memset(tb, 0, sizeof(struct rtattr *) * (CRYPTOCFGA_MAX + 1));
	while (RTA_OK(rta, res_len)) {
		if ((rta->rta_type <= CRYPTOCFGA_MAX) && (!tb[rta->rta_type]))
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta, res_len);
	}
	if (res_len) {
		goto out;
	}

	if (tb[CRYPTOCFGA_REPORT_HASH]) {
		struct rtattr *rta = tb[CRYPTOCFGA_REPORT_HASH];
		struct crypto_report_hash *rsh =
			(struct crypto_report_hash *) RTA_DATA(rta);
		handle->info.hash_digestsize = rsh->digestsize;
		handle->info.blocksize = rsh->blocksize;
	}
	if (tb[CRYPTOCFGA_REPORT_BLKCIPHER]) {
		struct rtattr *rta = tb[CRYPTOCFGA_REPORT_BLKCIPHER];
		struct crypto_report_blkcipher *rblk =
			(struct crypto_report_blkcipher *) RTA_DATA(rta);
		handle->info.blocksize = rblk->blocksize;
		handle->info.ivsize = rblk->ivsize;
		handle->info.blk_min_keysize = rblk->min_keysize;
		handle->info.blk_max_keysize = rblk->max_keysize;
	}
	if (tb[CRYPTOCFGA_REPORT_AEAD]) {
		struct rtattr *rta = tb[CRYPTOCFGA_REPORT_AEAD];
		struct crypto_report_aead *raead =
			(struct crypto_report_aead *) RTA_DATA(rta);
		handle->info.blocksize = raead->blocksize;
		handle->info.ivsize = raead->ivsize;
		handle->info.aead_maxauthsize = raead->maxauthsize;
	}
	if (tb[CRYPTOCFGA_REPORT_RNG]) {
		struct rtattr *rta = tb[CRYPTOCFGA_REPORT_RNG];
		struct crypto_report_rng *rrng =
			(struct crypto_report_rng *) RTA_DATA(rta);
		handle->info.rng_seedsize = rrng->seedsize;
	}
	ret = 0;

out:
	close(sd);
	return ret;
}

static int _kcaes_common_getinfo(struct kcaes_handle *handle,
		const char *ciphername)
{
	int ret = __kcaes_common_getinfo(handle, ciphername, 0);
	if (ret)
		return __kcaes_common_getinfo(handle, ciphername, 1);
	return 0;
}

static void _kcaes_handle_destroy_nofree(struct kcaes_handle *handle)
{
	if (!handle)
		return;
	if (handle->tfmfd != -1)
		close(handle->tfmfd);
	if (handle->opfd != -1)
		close(handle->opfd);
	if (handle->pipes[0] != -1)
		close(handle->pipes[0]);
	if (handle->pipes[1] != -1)
		close(handle->pipes[1]);
	kcaes_memset_secure(handle, 0, sizeof(struct kcaes_handle));
}

static void _kcaes_handle_destroy(struct kcaes_handle *handle)
{
	_kcaes_handle_destroy_nofree(handle);
	free(handle);
}

static int _kcaes_get_kernver(struct kcaes_handle *handle)
{
	struct utsname kernel;
	char *saveptr = NULL;
	char *res = NULL;

	if (uname(&kernel))
		return -errno;

	/* 3.15.0 */
	res = strtok_r(kernel.release, ".", &saveptr);
	if (!res) {
		return -EFAULT;
	}
	handle->sysinfo.kernel_maj = strtoul(res, NULL, 10);
	res = strtok_r(NULL, ".", &saveptr);
	if (!res) {
		return -EFAULT;
	}
	handle->sysinfo.kernel_minor = strtoul(res, NULL, 10);
	res = strtok_r(NULL, ".", &saveptr);
	if (!res) {
		return -EFAULT;
	}
	handle->sysinfo.kernel_patchlevel = strtoul(res, NULL, 10);

	return 0;
}

/* return true if kernel is greater or equal to given values, otherwise false */
static bool _kcaes_kernver_ge(struct kcaes_handle *handle, unsigned int maj,
		unsigned int minor, unsigned int patchlevel)
{
	if (maj < handle->sysinfo.kernel_maj)
		return true;
	if (maj == handle->sysinfo.kernel_maj) {
		if (minor < handle->sysinfo.kernel_minor)
			return true;
		if (minor == handle->sysinfo.kernel_minor) {
			if (patchlevel <= handle->sysinfo.kernel_patchlevel)
				return true;
		}
	}
	return false;
}

static void _kcaes_handle_flags(struct kcaes_handle *handle)
{
	/* new memory structure for AF_ALG AEAD interface */
	handle->flags.newtag = _kcaes_kernver_ge(handle, 4, 9, 0);

	/* older interfaces only processed 16 pages in a row */
	handle->flags.alg_max_pages = _kcaes_kernver_ge(handle, 4, 11, 0) ?
		UINT_MAX : ALG_MAX_PAGES;
}

static int _kcaes_allocated_handle_init(struct kcaes_handle *handle, const char *type,
		const char *ciphername)
{
	struct sockaddr_alg sa;
	int ret;


	handle->opfd = -1;
	handle->tfmfd = -1;
	handle->pipes[0] = -1;
	handle->pipes[1] = -1;

	ret = _kcaes_get_kernver(handle);
	if (ret)
		return ret;

	memset(&sa, 0, sizeof(sa));
	sa.salg_family = AF_ALG;
	snprintf((char *)sa.salg_type, sizeof(sa.salg_type),"%s", type);
	snprintf((char *)sa.salg_name, sizeof(sa.salg_name),"%s", ciphername);

	handle->tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (handle->tfmfd == -1) {
		ret = -errno;
		return ret;
	}

	if (bind(handle->tfmfd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
		ret = -errno;
		return ret;
	}

	ret = pipe(handle->pipes);
	if (ret) {
		ret = -errno;
		return ret;
	}

	ret = _kcaes_common_getinfo(handle, ciphername);
	if (ret) {
		ret = -errno;
		return ret;
	}

	_kcaes_handle_flags(handle);

	return ret;
}

static int _kcaes_handle_init(struct kcaes_handle **caller, const char *type,
		const char *ciphername)
{
	struct kcaes_handle *handle;
	int ret;

	handle = calloc(1, sizeof(struct kcaes_handle));
	if (!handle)
		return -ENOMEM;

	ret = _kcaes_allocated_handle_init(handle, type, ciphername);
	if (ret)
		_kcaes_handle_destroy(handle);
	else
		*caller = handle;

	return ret;
}

static int32_t _kcaes_cipher_crypt(struct kcaes_handle *handle, const uint8_t *in,
		uint32_t inlen, uint8_t *out, uint32_t outlen,
		int access, int enc)
{
	struct iovec iov;
	int32_t ret = 0;

	if (outlen > INT_MAX)
		return -EMSGSIZE;

	/*
	 * Using two syscalls with memcpy is faster than four syscalls
	 * without memcpy below the given threshold.
	 */
	if ((access == KCAES_ACCESS_HEURISTIC && inlen <= (1<<13)) ||
			access == KCAES_ACCESS_SENDMSG) {
		iov.iov_base = (void*)(uintptr_t)in;
		iov.iov_len = inlen;
		ret = _kcaes_common_send_meta_fd(handle, &handle->opfd, &iov, 1, enc, 0);
		if (0 > ret)
			return ret;
	} else {
		ret = _kcaes_common_send_meta_fd(handle, &handle->opfd, NULL, 0, enc,
				inlen ? MSG_MORE : 0);
		if (0 > ret)
			return ret;
		ret = _kcaes_common_vmsplice_chunk_fd(handle, &handle->opfd, in, inlen, 0);
		if (0 > ret)
			return ret;
	}

	return _kcaes_common_read_data_fd(handle, &handle->opfd, out, outlen);
}

static int32_t _kcaes_cipher_crypt_chunk(struct kcaes_handle *handle,
		const uint8_t *in, uint32_t inlen,
		uint8_t *out, uint32_t outlen,
		int access, int enc)
{
	int32_t totallen = 0;
	uint32_t maxprocess = sysconf(_SC_PAGESIZE) * ALG_MAX_PAGES;

	if (outlen > INT_MAX)
		return -EMSGSIZE;

	while (inlen) {
		uint32_t inprocess = inlen;
		uint32_t outprocess = outlen;
		int32_t ret = 0;

		/*
		 * We do not check that sysconf(_SC_PAGESIZE) * ALG_MAX_PAGES is
		 * a multiple of blocksize, because we assume that this is
		 * always the case.
		 */
		if (inlen > maxprocess)
			inprocess = maxprocess;
		if (outlen > maxprocess)
			outprocess = maxprocess;

		ret = _kcaes_cipher_crypt(handle, in, inprocess, out,
				outprocess, access, enc);
		if (ret < 0)
			return ret;

		totallen += inprocess;
		in += inprocess;
		inlen -= inprocess;
		out += ret;
		outlen -= ret;
	}

	return totallen;
}

// Export functions
int kcaes_cipher_init(struct kcaes_handle **handle, const char *ciphername)
{
	return _kcaes_handle_init(handle, "skcipher", ciphername);
}

void kcaes_cipher_destroy(struct kcaes_handle *handle)
{
	_kcaes_handle_destroy(handle);
}

int kcaes_cipher_setkey(struct kcaes_handle *handle,
		const uint8_t *key, uint32_t keylen)
{
	return _kcaes_common_setkey(handle, key, keylen);
}

int32_t kcaes_cipher_encrypt(struct kcaes_handle *handle,
		const uint8_t *in, uint32_t inlen,
		const uint8_t *iv,
		uint8_t *out, uint32_t outlen, int access)
{
	handle->cipher.iv = iv;
	return _kcaes_cipher_crypt_chunk(handle, in, inlen, out, outlen, access,
			ALG_OP_ENCRYPT);
}

int32_t kcaes_cipher_decrypt(struct kcaes_handle *handle,
		const uint8_t *in, uint32_t inlen,
		const uint8_t *iv,
		uint8_t *out, uint32_t outlen, int access)
{
	handle->cipher.iv = iv;
	return _kcaes_cipher_crypt_chunk(handle, in, inlen, out, outlen, access,
			ALG_OP_DECRYPT);
}

uint32_t kcaes_cipher_ivsize(struct kcaes_handle *handle)
{
	return handle->info.ivsize;
}

uint32_t kcaes_cipher_blocksize(struct kcaes_handle *handle)
{
	return handle->info.blocksize;
}
