#ifndef ASYNC_H
#define ASYNC_H


/* Include files */
#include <linux/module.h>
#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <asm/siginfo.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/namei.h>
# include <linux/scatterlist.h>
# include <linux/stat.h>
# include <linux/key-type.h>
# include <linux/ceph/decode.h>
# include <crypto/md5.h>
# include <crypto/aes.h>
# include <asm/scatterlist.h>
# include <keys/ceph-type.h>

/* just to test delays */
#include <linux/delay.h>
#include "async_data.h"

#include <linux/fdtable.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>

/* Defines */
#define QUEUE_DEAMON_NAME "work_queue_scheduler"

#define SIG_TEST 44
#define ENCRYPT_MAXLEN 10
#define SLEEPING_ENCRYPT_MAXLEN 10
#define ENPFX_LEN 4
#define ENPFX "/en."
#define ENCRYPT_FLAG 0;
#define MAX_PATH_SIZE 100


extern int concat_path(char **buf);
extern struct file *open_file(const char *path, int flags,int rights);
extern int remove_file(struct file *fp);
extern int check_file_path(const char *file);
extern char *alloc_encrypt_outfile_name(const char*path, int len, const char *filename);
extern char *alloc_encrypt_infile_name(const char*path, int len, const char *filename);
extern char *alloc_outfile_name(const char*path, int len, const char *filename);
extern int encrypt_file(const char *full_path_name,const char *filename, char *key, int keylen,int flag, char *out_filename, char* algo);
extern int cal_checksum_of_data(char * to_buffer);
extern int calc_md5(char *full_path_name,char *filename,char *buff, char *out_filename, char *algo);

struct main_container
{
	spinlock_t lock;   
	struct work_struct encryption_work;
	struct list_head pending_encryptions;
	int encrypt_len;
	struct list_head sleeping_encryptions;
	int sleeping_encrypt_len;
	
};


struct encryption_data
{
	/* 0 for decryption work
	 * 1 for encryption
	 * 2 for listing 
	 * 3 for removing 
	 * 4 for checksum 
	 */
	int opflag;
	int job_number;
	int pid; /* sending user process */
	//int flag; /*To encrypt or decrypt*/
	char *full_path_name; /*Need this to open the file*/
	char *filename;
	char *out_filename;
	char *key;
	int keylen;
	//char *md5_user_buff;
	struct list_head list; /* so we can join this to the main list_head */
	char *algo_name;

};


#endif

