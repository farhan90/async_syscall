#include "async.h"

void hash_to_hex(char *dst, char *src, size_t src_size)
 {
          int x;
  
          for (x = 0; x < src_size; x++)
                  sprintf(&dst[x * 2], "%.2x", (unsigned char)src[x]);
 }

int calc_md5(char *full_path_name,char *filename,char *out, char *out_filename, char *algo_name){

	char *src;
	char dst[16];
	struct file *input=NULL;
	struct file *output = NULL;
	char *ifile = NULL;
	char *ofile = NULL;
	int ret;
	loff_t pos=0;
	int bytes=0;
	struct hash_desc desc;
	struct scatterlist sg;	
	mm_segment_t oldfs=get_fs();
	set_fs(get_ds());

	printk("algo_name: %s\n", algo_name);
	if(strcmp(algo_name, MD_5)!= 0 && strcmp(algo_name, MD_4) != 0)
	{
		ret = -EINVAL;
		goto out;
	}

	ifile=alloc_encrypt_infile_name(full_path_name,MAX_PATH_SIZE+FILENAME_LEN,filename);
	
	if(IS_ERR(ifile)){
		ret=PTR_ERR(ifile);
		printk("In calc_md5 ifile error\n");
		goto out;

	}

	input=open_file(ifile,O_RDONLY,0);
	if(!input||IS_ERR(input)){
                ret=PTR_ERR(input);
                printk("Filp open failed in calc_md5\n");
                goto out;
        }

    ofile=alloc_outfile_name(full_path_name,MAX_PATH_SIZE+FILENAME_LEN,out_filename);
	
	if(IS_ERR(ofile)){
		ret=PTR_ERR(ofile);
		printk("In calc_md5 ofile error\n");
		goto out;

	}

	output=open_file(ofile,O_CREAT|O_WRONLY|O_TRUNC,input->f_dentry->d_inode->i_mode);
	if(!output||IS_ERR(output)){
                ret=PTR_ERR(output);
                printk("Filp open failed in calc_md5\n");
                goto out;
        }

		
	src=kmalloc(PAGE_SIZE,GFP_KERNEL);
	
	if(src==NULL){
		ret=-ENOMEM;
		goto out;
	}

	desc.flags=CRYPTO_TFM_REQ_MAY_SLEEP;
        desc.tfm=crypto_alloc_hash(algo_name,0,CRYPTO_ALG_ASYNC);

        if(IS_ERR(desc.tfm)){
                ret=PTR_ERR(desc.tfm);
                goto out_src;

        }


        ret=crypto_hash_init(&desc);
	if(ret){
                printk("Error in initializing hash_desc\n");
                goto out_free_hash;
        }


	memset(&dst,'\0',16);
	memset(src,'\0',PAGE_SIZE);
	while((bytes=vfs_read(input,src,PAGE_SIZE,&pos))>0){
		sg_init_one(&sg,src,bytes);

        	ret=crypto_hash_update(&desc,&sg,bytes);

        	if(ret){
                	printk("Error in hash_update\n");
                	goto out_free_hash;
        	}
		memset(src,'\0',PAGE_SIZE);		
	}

	
	if(bytes<0){
		printk("Error reading from input file for checksum\n");
		ret=bytes;
		goto out_free_hash;
	}

	ret=crypto_hash_final(&desc,dst);

	if(ret){

                printk("Error in hash_final\n");
                goto out_free_hash;
        }


	hash_to_hex(out,dst,16);

	/* Let's write to output file */
	pos = 0;
	bytes = vfs_write(output,out,32,&pos);
	if(bytes < 32)
	{
		printk("Error writing to output file the checksum\n");
		ret=bytes;
		goto out_free_hash;
	}

out_free_hash:
	crypto_free_hash(desc.tfm);

out_src:
	kfree(src);	

out:	
	if(input!=NULL){
		filp_close(input,NULL);
	}

	if(output!=NULL){
		filp_close(output,NULL);
	}

	if(ifile!=NULL){
		kfree(ifile);
	}
	if(ofile!=NULL){
		kfree(ofile);
	}	
	set_fs(oldfs);
	return ret;
}
