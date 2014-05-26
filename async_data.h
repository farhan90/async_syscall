#ifndef ASYNC_DATA_H
#define ASYNC_DATA_H

#define FILENAME_LEN 20
#define SIZE_OF_KEY_BUFFER 16
#define MAX_ALGO_NAME 20

/* ciphers */
#define CBC_AES "cbc(aes)"
#define CTR_AES "ctr(aes)"
#define XTS_AES "xts(aes)"
#define ECB_AES "ecb(aes)"
#define ECB_ARC4 "ecb(arc4)"
#define PCBC_FCRYPT "pcbc(fcrypt)"
#define ECB_DES3_EDE "ecb(des3_ede)"
#define CBC_DES3_EDE "cbc(des3_ede)"
#define ECB_TWOFISH "ecb(twofish)"
#define CBC_TWOFISH "cbc(twofish)"
#define CTR_TWOFISH "ctr(twofish)"
#define ECB_BLOWFISH "ecb(blowfish)"
#define CBC_BLOWFISH "cbc(blowfish)"
#define CTR_BLOWFISH "ctr(blowfish)"
#define CBC_DES "cbs(des)"
#define ECB_DES "ecb(des)"
#define ECB_CAMELLIA "ecb(camellia)"
#define CBC_CAMELLIA "cbc(camellia)"
#define SALSA20 "salsa20"


#define MD_5 "md5"
#define MD_4 "md4"
//#define SHA_256 "sha256"


struct req_buff
{
	char filename[FILENAME_LEN];
	int job_type;
	int job_number;
};

struct async_data
{
	/* 0 for decryption work
	 * 1 for encryption
	 * 2 for listing 
	 * 3 for removing 
	 * 4 for checksum 
	 */
	int opflag; /*Option or work to perform */
	//int eflag; /*Encrypt or decrypt flag */
	char *filename;
	char *out_filename;
	char *key; /*Key for encryption or decryption*/
	int keylen;
	int pid;
	struct req_buff **requested_buffer; /* malloc(sizeof(struct special) * buff_length); */
	char *md5_user_buff;
	int buff_length;
	int is_extra; /* how many more kernel has */
	int job_number;
	char *algo_name;
};



#endif
