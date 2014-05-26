#include "async.h"

int concat_path(char **buf){
    
    char *cwd,*temp;
    struct path pwd, root;
    pwd = current->fs->pwd;
    path_get(&pwd);
    root=  current->fs->root;
    path_get(&root);
    
    temp=kmalloc(GFP_KERNEL,MAX_PATH_SIZE);
    if(!temp){
        return -ENOMEM;
    }
    
    cwd = d_path(&pwd,temp,MAX_PATH_SIZE);
    
    strcpy(*buf,cwd);
    
    path_put(&pwd);
    path_put(&root);
    kfree(temp);
    return 0;
    
}




struct file* open_file(const char * path,int flags,int rights){
    struct file*filp=NULL;
    mm_segment_t oldfs;
    oldfs=get_fs();
    set_fs(get_ds());
    filp=filp_open(path,flags,rights);
    set_fs(oldfs);
    return filp;
    
}

int remove_file(struct file *fp){
    mm_segment_t oldfs=get_fs();
    int ret;
    struct dentry *fp_dentry=NULL;
    set_fs(get_ds());
    fp_dentry=fp->f_dentry;
    filp_close(fp,NULL);
    ret= vfs_unlink(fp_dentry->d_parent->d_inode,fp_dentry);
    set_fs(oldfs);
    return ret;
}



int check_file_path(const char * file){
    struct path path;
    int err;
    err=kern_path(file,LOOKUP_FOLLOW,&path);
    if(err)
        return err;
    else
        return 0;
    
}

// char *alloc_encrypt_outfile_name(const char*path, int len, const char *filename){
    
//     char *buf;
//     buf=kmalloc(len,GFP_KERNEL);
//     if(!buf){
//         return ERR_PTR(-ENOMEM);
//     }
//     memset(buf, '\n', len);
//     strcpy(buf, path);
//     strlcat(buf, ENPFX, len);
//     strlcat(buf, filename, len);
//     return buf;
// }


// char *alloc_decrypt_outfile_name(const char*path, int len, const char *filename){
    
//     char *buf;
//     buf=kmalloc(len,GFP_KERNEL);
//     if(!buf){
//         return ERR_PTR(-ENOMEM);
//     }
//     memset(buf, '\n', len);
//     strcpy(buf, path);
//     strlcat(buf, "/d", len);
//     strlcat(buf, filename, len);
//     return buf;
// }


char *alloc_encrypt_infile_name(const char*path, int len, const char *filename){
    
    char *buf;
    buf=kmalloc(len,GFP_KERNEL);
    if(!buf){
        return ERR_PTR(-ENOMEM);
    }
    memset(buf, '\n', len);
    strcpy(buf, path);
    strlcat(buf, "/", len);
    strlcat(buf, filename, len);
    return buf;
}
char *alloc_outfile_name(const char*path, int len, const char *filename){
    
    char *buf;
    buf=kmalloc(len,GFP_KERNEL);
    if(!buf){
        return ERR_PTR(-ENOMEM);
    }
    memset(buf, '\n', len);
    strcpy(buf, path);
    strlcat(buf, "/", len);
    strlcat(buf, filename, len);
    return buf;
}


/* Main encrypt function
 * referenced from ceph_aes_encrypt() function
 * returns length encrypted
 */
int encrypt_data(const void *key, int length_key, void *to_buffer, const void *from_buffer, size_t *to_length, 
    size_t from_length, char *algo_name){
    
    struct scatterlist scatter_list_src[2];
    struct scatterlist scatter_list_dest[1];
    struct crypto_blkcipher *tfm = crypto_alloc_blkcipher(algo_name, 0, CRYPTO_ALG_ASYNC);
    struct blkcipher_desc desc = { .tfm = tfm, .flags = 0 };
    size_t null_padding = (0x10 - (from_length & 0x0f));
    int return_value = 0;
    char padding_array[48];
    
    printk("algo_name: %s\n", algo_name);
    /* check to see if the cipher struct is set properly */
    if(IS_ERR(tfm))
    {
        printk("Error in setting tfm\n");
        return PTR_ERR(tfm);
    }
    memset(padding_array, null_padding, null_padding);
    
    *to_length = from_length + null_padding;
    
    /* let's set the key for the cipher */
    crypto_blkcipher_setkey((void *)tfm, key, length_key);
	sg_init_table(scatter_list_src, 2);
	sg_set_buf(&scatter_list_src[0], from_buffer, from_length);
	sg_set_buf(&scatter_list_src[1], padding_array, null_padding);
	sg_init_table(scatter_list_dest, 1);
	sg_set_buf(scatter_list_dest, to_buffer,*to_length);
    
    /* let's start encrypting */
    return_value = crypto_blkcipher_encrypt(&desc, scatter_list_dest, scatter_list_src, from_length + null_padding);
    
    /* free up the blk cipher */
    crypto_free_blkcipher(tfm);
    
    if (return_value < 0)
    {
        printk(KERN_CRIT "crypto_blcipher encryption failed with errno %d.\n",return_value);
    }
    
    return return_value;
    
}

int decrypt_data(const void *key, int length_key, void *to_buffer, const void *from_buffer, 
    size_t *to_length, size_t from_length, char *algo_name)
{

	int return_value =0;
	int end_element;
	char padding_array[48];
	struct scatterlist scatter_list_src[1];
    struct scatterlist scatter_list_dest[2];
	struct crypto_blkcipher *tfm = crypto_alloc_blkcipher(algo_name, 0, CRYPTO_ALG_ASYNC);
	struct blkcipher_desc desc = { .tfm = tfm };
    
    printk("algo_name: %s\n", algo_name);
    
	/* check to see if the cipher struct is set properly */
    if(IS_ERR(tfm))
    {
        return PTR_ERR(tfm);
    }
    
	/* Setting the key for Block cipher */
	crypto_blkcipher_setkey((void *)tfm, key, length_key);
	sg_init_table(scatter_list_src, 1);
	sg_init_table(scatter_list_dest, 2);
	sg_set_buf(scatter_list_src, from_buffer, from_length);
	sg_set_buf(&scatter_list_dest[0], to_buffer, *to_length);
	sg_set_buf(&scatter_list_dest[1], padding_array, sizeof(padding_array));
    
	/* let's decrypt using crypto_blkcipher */
	return_value = crypto_blkcipher_decrypt(&desc, scatter_list_dest, scatter_list_src, from_length);
    /* Free up the blk cipher */
	crypto_free_blkcipher(tfm);
    
	if (return_value < 0) {
        printk(KERN_CRIT "crypto_blcipher decryption failed 1.\n");
		return return_value;
	}
    
	if (from_length <= *to_length)
		end_element = ((char *)to_buffer)[from_length - 1];
	else
		end_element = padding_array[from_length - *to_length - 1];
    
	if (end_element <= 16 && from_length >= end_element) {
        
		*to_length = from_length - end_element;
	}
	else 
    {
        printk(KERN_CRIT "crypto_blcipher decryption failed 2.\n");
        return -EPERM;  //bad padding
    }
    return return_value;
}


/*
 * Read "len" bytes from file into "buf".
 * "buf" is in kernel space.
 */
int wrapfs_read_file(struct file *file, char *buf, int len)
{
    mm_segment_t oldfs;
    int bytes = 0;
    /* Disabling transaltion, we are already operating in kernel mode */
    oldfs = get_fs();
    set_fs(KERNEL_DS);
    bytes = file->f_op->read(file, buf, len, &file->f_pos);
    set_fs(oldfs);
    
    if(bytes <=0)
    {
        bytes = -EBADF;
        printk(KERN_CRIT "file read failed!\n");
    }
    else
    {
        printk(KERN_CRIT "bytes read: %d\n", bytes);
    }
    return bytes;
}

/*
 * Write function: Writes len bytes to file from buf
 *
 */
int wrapfs_write_file(struct file *file, char *buf, int len)
{
    mm_segment_t oldfs;
    int bytes = 0;
    oldfs = get_fs();
    set_fs(KERNEL_DS);
    bytes = file->f_op->write(file, buf, len, &file->f_pos);
    set_fs(oldfs);
    if(bytes <=0)
    {
        bytes = -EBADF;
        printk(KERN_CRIT "file write failed!\n");
    }
    else
    {
        printk(KERN_CRIT "bytes written: %d\n", bytes);
    }
    return bytes;
}

int encrypt_file_helper(struct file *input, struct file *output, char *key, int keylen,int flag, char *algo_name)
{
    //mm_segment_t oldfs;
    //loff_t offset=0;
    //loff_t pos=0;
    int readBytes = 0;
    int writtenBytes = 0;
    int size_of_input_file = 0;
    int actual_length_to_be_used = 0;
    int return_value = 0;
    int i;
    /* 0 means don't clean, 1 means clean */
    int clean_output_file = 0;
    ssize_t *length_encrypted = kmalloc(sizeof(ssize_t), GFP_KERNEL);
    /* buffers for transfers */
    char *from = kmalloc(PAGE_SIZE, GFP_KERNEL);
    char *to = kmalloc(PAGE_SIZE, GFP_KERNEL);
    
    /* let's check if kmalloc has worked */
    if(from == NULL || to == NULL)
    {
        return_value = -ENOMEM;
        printk("Error in allocating space for buffers\n");
        goto cleanup_this_house;
    }

    size_of_input_file = input->f_dentry->d_inode->i_size;


    /* When decrypting, we move the input file pointer 16 spaces and also verify the key as well */
    if (flag == 0)
    {
        memset(from,'\0', PAGE_SIZE);
        readBytes = wrapfs_read_file(input, from, 16);
        if(readBytes <= 0)
        {
            return_value = readBytes; //error returned by the read method.
            clean_output_file = 1; //remove partial output file
            goto cleanup_this_house;
        }
        /* Let's compare the key */
        for (i = 0; i < SIZE_OF_KEY_BUFFER; i++)
        {
            if (from[i] != key[i])
            {
                printk(KERN_CRIT "Key entered and preamble on the input file don't match\n");
                return_value = -EINVAL;
                clean_output_file = 1;
                goto cleanup_this_house;
            }
        }
        input->f_pos = 16;
        printk(KERN_CRIT "Key matched successfully\n");

    }
    
    /* This is the preamble portion, where we write the key on the file */
    if (flag == 1)
    {
        printk(KERN_CRIT "Writing key on the output file\n");
        if ((writtenBytes = wrapfs_write_file(output, key, 16)) <1)
        {
            printk(KERN_CRIT "Error while writing key on the output file.\n");
            return_value = -EIO;
            clean_output_file = 1;
            goto cleanup_this_house;
        }
        output->f_pos = 16;
        printk(KERN_CRIT "Preamble written successfully on the output file\n");

    }
    
    /* if decryption, then total bytes are reduced by 16, coz 16 is the preamble */
    if(flag == 0)
        size_of_input_file = size_of_input_file - 16;
    
    printk(KERN_CRIT "*******************************\n");
    printk(KERN_CRIT "We are ready to encrypt/decrypt\n");
    printk(KERN_CRIT "*******************************\n");

    /* Main while loop, that reads, en/de crypt and then writes */
    while(size_of_input_file > 0)
    {
        actual_length_to_be_used = 0;
        readBytes = 0;
        writtenBytes = 0;
        memset(from, '0', PAGE_SIZE);
        memset(to, '0', PAGE_SIZE);
        
        /* if decryption flag is specified */
        if (flag == 0)
        {
            if (size_of_input_file > (PAGE_SIZE))
            {
                actual_length_to_be_used = PAGE_SIZE;
                size_of_input_file = size_of_input_file - actual_length_to_be_used ;
            }
            else
            {
                actual_length_to_be_used = size_of_input_file;
                size_of_input_file = 0;
            }
        }
        
        /* 16 bytes are used for preamble, so set the buffer that will be en/de crypted according to the flag */
        if (flag == 1)
        {
            
            if (size_of_input_file > (PAGE_SIZE - 16))
            {
                actual_length_to_be_used = PAGE_SIZE - 16;
                size_of_input_file = size_of_input_file - actual_length_to_be_used ;
            }
            else
            {
                actual_length_to_be_used = size_of_input_file;
                size_of_input_file = 0;
            }
        }
        
        
        /* reading bytes depending upon the appropriate size */
        readBytes = wrapfs_read_file(input, from, actual_length_to_be_used);
        if(readBytes <= 0)
        {
            return_value = readBytes; //error returned by the read method.
            clean_output_file = 1;
            goto cleanup_this_house;
        }
        
        /* encrypt */
        if(flag ==1)
        {
            printk(KERN_CRIT "Encrypting...\n");
            return_value = encrypt_data(key, keylen, to, from, length_encrypted, actual_length_to_be_used, algo_name);
            if(return_value < 0)
            {
                printk(KERN_CRIT "cypto_blkcipher Encryption Failed.\n");
                clean_output_file = 1;
                goto cleanup_this_house;
            }
        }
        
        /* dencrypt */
        if(flag ==0)
        {
            printk(KERN_CRIT "Decrypting...\n");
            return_value = decrypt_data(key, keylen, to, from, length_encrypted, actual_length_to_be_used, algo_name);
            if(return_value < 0)
            {
                printk(KERN_CRIT "cypto_blkcipher Decryption Failed.\n");
                clean_output_file = 1;
                goto cleanup_this_house;
            }
        }
        writtenBytes = wrapfs_write_file(output, to, *length_encrypted);
        if(writtenBytes <=0)
        {
            return_value = writtenBytes; //error returned by the write method.
            clean_output_file = 1;
            goto cleanup_this_house;
        }
        
        
    }

    
cleanup_this_house:
    kfree(to);
    kfree(from);
    //set_fs(oldfs);
    return return_value;
    
}


int encrypt_file(const char *full_path_name,const char *filename, char *key, int keylen,int flag, char *out_filename, char *algo_name){
    
    int ret;
    char *ofile_name;
    char *infile_name;
    struct file *input=NULL;
    struct file *output;
    
    
    
    infile_name=alloc_encrypt_infile_name(full_path_name,MAX_PATH_SIZE + FILENAME_LEN,filename);
    
    if(IS_ERR(infile_name)){
        ret=PTR_ERR(infile_name);
        printk("getting input file name failed\n");
        goto out_close;
    }
    
    input=open_file(infile_name,O_RDONLY,0);
    
    if(!input||IS_ERR(input)){
        ret=PTR_ERR(input);
        printk("Opening input file for encryption failed\n");
        goto out;
    }
    
    
    /*create output file*/
    // if(flag==1)
    //     ofile_name=alloc_encrypt_outfile_name(full_path_name,MAX_PATH_SIZE + FILENAME_LEN,filename);
    
    // else
    //     ofile_name=alloc_decrypt_outfile_name(full_path_name,MAX_PATH_SIZE + FILENAME_LEN,filename);

    ofile_name=alloc_outfile_name(full_path_name,MAX_PATH_SIZE + FILENAME_LEN,out_filename);
    
    if(IS_ERR(ofile_name)){
        ret=PTR_ERR(ofile_name);
        goto out_close;
    }
    
    printk("The output file is %s\n",ofile_name);
    output=open_file(ofile_name,O_CREAT|O_RDWR|O_TRUNC,input->f_dentry->d_inode->i_mode);
    
    if(!output||IS_ERR(output)){
        ret=PTR_ERR(output);
        printk("Opening outfile for encryption failed\n");
        goto out_free;
    }
    
    ret=encrypt_file_helper(input,output,key,keylen,flag, algo_name);
    if(ret<0){
        remove_file(output);
        goto out_free;
    }
    
    filp_close(output,NULL);
    
    
out_free:
    if(ofile_name!=NULL){
        kfree(ofile_name);
    }
    
out_close:
    filp_close(input,NULL);
    
out:
    if(infile_name!=NULL){
        kfree(infile_name);
    }
    return ret;
    
}


