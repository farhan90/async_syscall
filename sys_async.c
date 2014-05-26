#include "async.h"


asmlinkage extern long (*sysptr)(void *arg);

/* Variables */
/* Main work queue */
struct workqueue_struct *work_queue;

/* Super struct */
struct main_container *mc;

//static int global_job_number;


// static void current_dir(void)
// {

//    char *cwd;
//    struct path pwd, root;
//    char *buf = (char *)kmalloc(GFP_KERNEL,100*sizeof(char));
//    pwd = current->fs->pwd;
//    path_get(&pwd);
//    root=  current->fs->root;
//    path_get(&root);
//    cwd = d_path(&pwd,buf,100*sizeof(char));
//    printk(KERN_ALERT "Hello,the current working directory is \n %s",cwd);

//    return;
// }


static int create_work_queue(void)
{
    int r = 0;
    printk(KERN_ERR "Creating work_queue\n");
    work_queue = create_workqueue(QUEUE_DEAMON_NAME);
    if (work_queue == NULL)
    {
        printk(KERN_ERR "Couldn't create work_queue properly.\n");
        r = -EINVAL;
    }
    return r;
}

static void destroy_work_queue(void)
{
    printk(KERN_ERR "Removing work_queue\n");
    destroy_workqueue(work_queue);
}

/* who: 0 means kernel signal
 *      otherwise, regular singal to user
 */
static int send_signal_to_user(int prid, int sig, int error, int who, int band)
{
    struct siginfo info;
    struct task_struct *t;
    int ret = 0;
    
    printk(KERN_ERR "prid: %d\n", prid);
    
    /* send the signal */
    memset(&info, 0, sizeof(struct siginfo));
    info.si_signo = sig;
    info.si_errno = error;
    if(who != 0)
    {
        info.si_band = band;
    }
    /* this should be SI_KERNEL when kernel is sending something to user */
    if(who == 0)
    {
        info.si_code = SI_KERNEL;
    }
    else
    {
        info.si_code = SI_QUEUE;
    }
    
    info.si_int = sig;
    
    rcu_read_lock();
    //t = find_task_by_pid_type(PIDTYPE_PID, pid);  //find the task_struct associated with this pid
    t = pid_task(find_pid_ns(prid, &init_pid_ns), PIDTYPE_PID);
    if(t == NULL)
    {
        printk(KERN_ERR "no such prid\n");
        rcu_read_unlock();
        ret = -ENODEV;
        goto out;
    }
    rcu_read_unlock();
    ret = send_sig_info(sig, &info, t);    //send the signal
    if (ret < 0)
    {
        printk(KERN_ERR "error sending signal\n");
        goto out;
    }
    
out:
    return ret;
}

static struct encryption_data *give_me_encryption_work(struct main_container *mc)
{
    struct encryption_data *edata;
    
    edata = list_first_entry(&mc->pending_encryptions,
                             struct encryption_data, list);
    list_del(&edata->list);
    mc->encrypt_len--;
    return edata;
}

static struct encryption_data *give_me_encryption_work_sleeping(struct main_container *mc)
{
    struct encryption_data *edata;
    
    edata = list_first_entry(&mc->sleeping_encryptions,
                             struct encryption_data, list);
    /* this removes it from the current list, but reinitialize the
     * list pointer to add to another list
     */
    list_del_init(&edata->list);
    mc->sleeping_encrypt_len--;
    return edata;
}

static void encryption_work(struct work_struct *work)
{
    struct main_container *mc;
    struct encryption_data *edata;
    struct encryption_data *edata_sleeping;
    int ret = 0;
    unsigned long flags;
    //int a;	

    /* test only */
    //char * to_buffer = kmalloc(16, GFP_KERNEL);    

    printk(KERN_ERR "encryption_work thread is activated\n");
    //current_dir();
    
    mc = container_of(work, struct main_container, encryption_work);
    
    /* test */
    //msleep(5000);
    
    /* LOCK () */
    printk(KERN_ERR "Consumer: ********* Grabbing lock *************\n");
    spin_lock_irqsave(&mc->lock, flags);
    
    if(mc->encrypt_len==0)
    {
        /*UNLOCK*/
        spin_unlock_irqrestore(&mc->lock, flags);
        printk(KERN_ERR "Consumer: ********* Released lock *************\n");
        return;
    }
    
    edata = give_me_encryption_work(mc);
    
    /* Notify the sleeping user*/
    if(mc->sleeping_encrypt_len > 0)
    {
        
        edata_sleeping = give_me_encryption_work_sleeping(mc);
        
        /* Let's add this to current encryption queue */
        list_add_tail(&edata_sleeping->list, &mc->pending_encryptions);
        mc->encrypt_len++;
        
        printk(KERN_ERR "Consumer: waking up a peid: %d\n", edata_sleeping->pid);
        send_signal_to_user(edata_sleeping->pid, SIGCONT, 0, 0, 0);
    }
    
    
    /* UNLOCK() */
    spin_unlock_irqrestore(&mc->lock, flags);
    printk(KERN_ERR "Consumer: ********* Released lock *************\n");
    //Do the file ops here
    
    //printk(KERN_ERR "pid from linked list: %d\n", edata->pid);
    if(edata->opflag == 0 || edata->opflag == 1)
    {
        printk(KERN_ERR "************** EN/DE CRYPTION *************\n");
        ret=encrypt_file(edata->full_path_name,edata->filename,edata->key,
            edata->keylen,edata->opflag, edata->out_filename, edata->algo_name);
    }
    else if(edata->opflag == 4)
    {
        char to_buff[33];   
        printk(KERN_ERR "************** CHECKSUM *************\n");
        memset(to_buff,'\0',32);  
        ret=calc_md5(edata->full_path_name,edata->filename,to_buff, edata->out_filename, edata->algo_name);
        printk("The Checksum value is: %s\n",to_buff);
    }
    

    send_signal_to_user(edata->pid, SIG_TEST, edata->job_number, 1, ret);
    
    //memset(to_buff,'\0',32);
    kfree(edata->full_path_name);
    kfree(edata->filename);
    kfree(edata->out_filename);
    kfree(edata->algo_name);
    if(edata->opflag == 0 || edata->opflag == 1)
    {
        kfree(edata->key);
    }
    kfree(edata);
    
    
    if(queue_work(work_queue, &mc->encryption_work) == 0)
    {
        printk(KERN_ERR "Work didn't get queued properly\n");
    }
    else
        printk(KERN_ERR "encryption_work has been queued\n");
    
    printk(KERN_ERR "leaving encryption_work thread\n");
}

int validate_args(void *args, struct async_data *buf){
	int ret=0;
	//struct path fpath;    
	//struct inode *inode=NULL;

	if(args==NULL){
		return -EINVAL;
	}
    
    /* let's see if we have access to the arguments that were passed to us */
    if(!access_ok(VERIFY_READ, args, sizeof(struct async_data)))
    {
        
        printk(KERN_CRIT "Access to the arguments passed is denied\n");
        return -EFAULT;
    }
    
    if(copy_from_user(buf, (struct async_data *)args, sizeof(struct async_data))!=0)
    {
        printk("Copy from user has failed\n");
        return -EINVAL;
    }	
    
    return ret;
}

int check_permissions(void *args, struct async_data *buf){
    int ret=0;
    struct path fpath;    
    struct inode *inode=NULL;

    ret=user_path(buf->filename,&fpath);
    if(ret){
    printk("Could not get user path in validate args\n");
    return ret;
    }   

    inode=fpath.dentry->d_inode;    
    ret=inode_permission(inode,MAY_READ);
    if(ret<0)
    {
        printk("No inode read permissions\n");
    } 
    printk("We have read permissions\n"); 

    /* Output file */
    ret=user_path(buf->out_filename,&fpath);
    if(ret)
    {
        printk("Output file doens't exist, so we will create one\n");
        ret = 0;
    }   
    else
    {
        inode = fpath.dentry->d_inode;    
        ret=inode_permission(inode,MAY_WRITE);
        if(ret<0)
        {
            printk("No inode read permissions\n");
        } 
        printk("We have write permissions\n"); 
    } 

    
    return ret;
}



int encryption_work_producer(struct async_data *buf)
{
    struct encryption_data *en_data = NULL;
    int pid;
    unsigned long flags;
    int val = 0;

    pid = buf->pid;
    if(buf->filename == NULL || buf->out_filename == NULL || buf->key == NULL || buf->keylen == 0 || buf->pid == 0)
    {
        printk("Invalid argument passed by user process\n");
        val = -EINVAL;
        goto out;
    }
    /* let's setup encryption data struct and then we will
     * queue it into the main encryption linked list
     */
    en_data = kmalloc(sizeof(struct encryption_data), GFP_KERNEL);
    if(en_data == NULL)
    {
        val = -ENOMEM;
        printk(KERN_ERR "ERROR: (async) Not enough memory to allocate for encryption_data struct\n");
        goto out;
    }

    en_data->pid = pid;

    en_data->full_path_name = kmalloc(FILENAME_LEN+MAX_PATH_SIZE, GFP_KERNEL); /* missing error check */
    if(en_data->full_path_name==NULL)
    {
        val=-ENOMEM;
        printk("Not enough memory to allocate filename\n");
        goto out;
    }
    
    en_data->filename=kmalloc(FILENAME_LEN,GFP_KERNEL);
    if(en_data->filename==NULL)
    {
        val=-ENOMEM;
        goto out_free_full_path;
    }

    en_data->out_filename=kmalloc(FILENAME_LEN,GFP_KERNEL);
    if(en_data->out_filename==NULL)
    {
        val=-ENOMEM;
        goto out_free_filename;
    }
    
    en_data->key=kmalloc(SIZE_OF_KEY_BUFFER,GFP_KERNEL);
    if(en_data->key==NULL)
    {
        val=-ENOMEM;
        goto out_free_out_filename;
    }

    en_data->algo_name = kmalloc(MAX_ALGO_NAME,GFP_KERNEL);
    if(en_data->algo_name==NULL)
    {
        val=-ENOMEM;
        goto out_free_key;
    }


   
    //printk("In the producer before setting the %s\n",arg->md5_user_buff);
    //printk("Before setting buf%d \n", arg->md5_user_buff);   
    //memcpy(&en_data->md5_user_buff,&arg->md5_user_buff,sizeof(int));
    //en_data->md5_user_buff = arg->md5_user_buff;

    //printk("After setting %d \n", en_data->md5_user_buff);	

    memset(en_data->filename, '\0', FILENAME_LEN);
    memset(en_data->out_filename, '\0', FILENAME_LEN);
    memset(en_data->full_path_name,'\0',FILENAME_LEN+MAX_PATH_SIZE);
    memset(en_data->key,'\0',SIZE_OF_KEY_BUFFER);
    memset(en_data->algo_name, '\0', MAX_ALGO_NAME);
    
    strcpy(en_data->key,buf->key);
    en_data->keylen=buf->keylen;
    //en_data->flag=buf->eflag;
    strcpy(en_data->filename, buf->filename);
    strcpy(en_data->out_filename, buf->out_filename);
    strcpy(en_data->algo_name, buf->algo_name);
    en_data->opflag = buf->opflag;
    en_data->job_number = buf->job_number;

    val = concat_path(&(en_data->full_path_name));
    if(val<0){
        printk("Error setting path in producer\n");
        goto out;
    }
    
    INIT_LIST_HEAD(&en_data->list);
    
    printk(KERN_ERR "********* Grabbing lock *************\n");
    /* This flags is just used to store the current state, and we
     * return it when unlocking
     */
    spin_lock_irqsave(&mc->lock, flags);
    
    /* Now let's add it the main encryption linked list */
    /* if pending has reached it's limit, but sleeping has space */
    if(mc->encrypt_len >= ENCRYPT_MAXLEN && mc->sleeping_encrypt_len < SLEEPING_ENCRYPT_MAXLEN)
    {
        //en_data->job_number = global_job_number;
        //global_job_number++;
        list_add_tail(&en_data->list, &mc->sleeping_encryptions);
        mc->sleeping_encrypt_len++;
        /*UNLOCK*/
        spin_unlock_irqrestore(&mc->lock, flags);
        printk(KERN_ERR "********* Released lock *************\n");
        
        printk(KERN_ERR "Putting pid: %d to sleep\n", pid);
        val = send_signal_to_user(pid, SIGSTOP, 0, 0, 0);
        goto out;
    }
    /* both queues are full */
    else if(mc->encrypt_len >= ENCRYPT_MAXLEN && mc->sleeping_encrypt_len >= SLEEPING_ENCRYPT_MAXLEN)
    {
        val=-EBUSY;
        /*UNLOCK*/
        spin_unlock_irqrestore(&mc->lock, flags);
        printk(KERN_ERR "********* Released lock *************\n");
        kfree(en_data->full_path_name);
        kfree(en_data->filename);
        kfree(en_data->out_filename);
        kfree(en_data->key);
        kfree(en_data->algo_name);
        kfree(en_data);
        goto out;
    }
    
    //en_data->job_number = global_job_number;
    //global_job_number++;
    list_add_tail(&en_data->list, &mc->pending_encryptions);
    mc->encrypt_len++;
    
    //queue_work(work_queue, &mc->encryption_work);
    printk(KERN_ERR "filename %s\n key: %s\n keylen: %d\n", en_data->filename, en_data->key, en_data->keylen);
    
    /* UNLOCK() */
    spin_unlock_irqrestore(&mc->lock, flags);
    printk(KERN_ERR "********* Released lock *************\n");
    
    /* Work_queue has it's own locks. so DO NOT include this inside a lock */
    if(queue_work(work_queue, &mc->encryption_work) == 0)
    {
        printk(KERN_ERR "Work didn't get queued properly\n");
    }
    else
    {
        printk(KERN_ERR "encryption_work has been queued\n");
    } 
    goto out; 
  
out_free_key:
    kfree(en_data->key);  
out_free_out_filename:
    kfree(en_data->out_filename);
out_free_filename:
    kfree(en_data->filename);
out_free_full_path:
    kfree(en_data->full_path_name);
    
out:
    if(buf != NULL)
    {
        kfree(buf);
    }
    return val;
}


int checksum_work_producer(struct async_data *buf)
{
    struct encryption_data *en_data = NULL;
    int pid;
    unsigned long flags;
    int val = 0;

    pid = buf->pid;
    if(buf->filename == NULL || buf->out_filename == NULL || buf->pid == 0)
    {
        printk("Invalid argument passed by user process\n");
        val = -EINVAL;
        goto out;
    }
    /* let's setup encryption data struct and then we will
     * queue it into the main encryption linked list
     */
    en_data = kmalloc(sizeof(struct encryption_data), GFP_KERNEL);
    if(en_data == NULL)
    {
        val = -ENOMEM;
        printk(KERN_ERR "ERROR: (async) Not enough memory to allocate for encryption_data struct\n");
        goto out;
    }

    en_data->pid = pid;

    en_data->full_path_name = kmalloc(FILENAME_LEN+MAX_PATH_SIZE, GFP_KERNEL); /* missing error check */
    if(en_data->full_path_name==NULL)
    {
        val=-ENOMEM;
        printk("Not enough memory to allocate filename\n");
        goto out;
    }
    
    en_data->filename=kmalloc(FILENAME_LEN,GFP_KERNEL);
    if(en_data->filename==NULL)
    {
        val=-ENOMEM;
        goto out_free_full_path;
    }

    en_data->out_filename=kmalloc(FILENAME_LEN,GFP_KERNEL);
    if(en_data->out_filename==NULL)
    {
        val=-ENOMEM;
        goto out_free_filename;
    }

    en_data->algo_name=kmalloc(MAX_ALGO_NAME,GFP_KERNEL);
    if(en_data->algo_name==NULL)
    {
        val=-ENOMEM;
        goto out_free_out_filename;
    }
    
    // en_data->key=kmalloc(SIZE_OF_KEY_BUFFER,GFP_KERNEL);
    // if(en_data->key==NULL)
    // {
    //     val=-ENOMEM;
    //     goto out_free_out_filename;
    // }
   
    //printk("In the producer before setting the %s\n",arg->md5_user_buff);
    //printk("Before setting buf%d \n", arg->md5_user_buff);   
    //memcpy(&en_data->md5_user_buff,&arg->md5_user_buff,sizeof(int));
    //en_data->md5_user_buff = arg->md5_user_buff;

    //printk("After setting %d \n", en_data->md5_user_buff);    

    memset(en_data->filename, '\0', FILENAME_LEN);
    memset(en_data->out_filename, '\0', FILENAME_LEN);
    memset(en_data->full_path_name,'\0',FILENAME_LEN+MAX_PATH_SIZE);
    memset(en_data->algo_name, '\0', MAX_ALGO_NAME);
    //memset(en_data->key,'\0',SIZE_OF_KEY_BUFFER);
    
    //strcpy(en_data->key,buf->key);
    //en_data->keylen=buf->keylen;
    //en_data->flag=buf->eflag;
    strcpy(en_data->filename, buf->filename);
    strcpy(en_data->out_filename, buf->out_filename);
    strcpy(en_data->algo_name, buf->algo_name);
    en_data->opflag = buf->opflag;
    en_data->job_number = buf->job_number;

    val = concat_path(&(en_data->full_path_name));
    if(val<0){
        printk("Error setting path in producer\n");
        goto out;
    }
    
    INIT_LIST_HEAD(&en_data->list);
    
    printk(KERN_ERR "********* Grabbing lock *************\n");
    /* This flags is just used to store the current state, and we
     * return it when unlocking
     */
    spin_lock_irqsave(&mc->lock, flags);
    
    /* Now let's add it the main encryption linked list */
    /* if pending has reached it's limit, but sleeping has space */
    if(mc->encrypt_len >= ENCRYPT_MAXLEN && mc->sleeping_encrypt_len < SLEEPING_ENCRYPT_MAXLEN)
    {
        //en_data->job_number = global_job_number;
        //global_job_number++;
        list_add_tail(&en_data->list, &mc->sleeping_encryptions);
        mc->sleeping_encrypt_len++;
        /*UNLOCK*/
        spin_unlock_irqrestore(&mc->lock, flags);
        printk(KERN_ERR "********* Released lock *************\n");
        
        printk(KERN_ERR "Putting pid: %d to sleep\n", pid);
        val = send_signal_to_user(pid, SIGSTOP, 0, 0, 0);
        goto out;
    }
    /* both queues are full */
    else if(mc->encrypt_len >= ENCRYPT_MAXLEN && mc->sleeping_encrypt_len >= SLEEPING_ENCRYPT_MAXLEN)
    {
        val=-EBUSY;
        /*UNLOCK*/
        spin_unlock_irqrestore(&mc->lock, flags);
        printk(KERN_ERR "********* Released lock *************\n");
        kfree(en_data->full_path_name);
        kfree(en_data->filename);
        kfree(en_data->out_filename);
        kfree(en_data->algo_name);
        kfree(en_data);
        goto out;
    }
    
    //en_data->job_number = global_job_number;
    //global_job_number++;
    list_add_tail(&en_data->list, &mc->pending_encryptions);
    mc->encrypt_len++;
    
    //queue_work(work_queue, &mc->encryption_work);
    //printk(KERN_ERR "filename %s\n key: %s\n keylen: %d\n", en_data->filename, en_data->key, en_data->keylen);
    
    /* UNLOCK() */
    spin_unlock_irqrestore(&mc->lock, flags);
    printk(KERN_ERR "********* Released lock *************\n");
    
    /* Work_queue has it's own locks. so DO NOT include this inside a lock */
    if(queue_work(work_queue, &mc->encryption_work) == 0)
    {
        printk(KERN_ERR "Work didn't get queued properly\n");
    }
    else
    {
        printk(KERN_ERR "encryption_work has been queued\n");
    } 
    goto out; 
    
out_free_out_filename:
    kfree(en_data->out_filename);
out_free_filename:
    kfree(en_data->filename);
out_free_full_path:
    kfree(en_data->full_path_name);
    
out:
    if(buf != NULL)
    {
        kfree(buf);
    }
    return val;
}

int list_jobs(struct async_data *buf)
{
    int i = 0;
    int extra = 0;
    struct list_head *ptr;
    struct encryption_data *en_data;
    unsigned long flags;

    printk(KERN_ERR "********* Grabbing lock *************\n");
    spin_lock_irqsave(&mc->lock, flags);

    list_for_each(ptr, &mc->pending_encryptions)
    {
        en_data = list_entry(ptr, struct encryption_data, list);
        if(buf->pid == en_data->pid)
        {
            if(i < buf->buff_length)
            {
                strcpy((void *)&buf->requested_buffer[i]->filename, en_data->filename);
                buf->requested_buffer[i]->job_type = en_data->opflag;
                buf->requested_buffer[i]->job_number = en_data->job_number;
                i++;
            }
            else
            {
                extra++;
            }
        }
    }
    buf->is_extra = extra;
    spin_unlock_irqrestore(&mc->lock, flags);
    printk(KERN_ERR "********* Released lock *************\n");
    return 0;
}

int remove_job(struct async_data *buf)
{
    int val = -1;
    struct list_head *ptr;
    struct encryption_data *en_data;
    unsigned long flags;

    printk(KERN_ERR "remove: ********* Grabbing lock *************\n");
    spin_lock_irqsave(&mc->lock, flags);

    list_for_each(ptr, &mc->pending_encryptions)
    {
        en_data = list_entry(ptr, struct encryption_data, list);
        if(buf->pid == en_data->pid && buf->job_number == en_data->job_number)
        {
            __list_del_entry(&en_data->list);
            mc->encrypt_len--;
            kfree(en_data->full_path_name);
            kfree(en_data->filename);
            kfree(en_data->out_filename);
            if(en_data->opflag == 0 || en_data->opflag == 1)
                kfree(en_data->key);
            kfree(en_data);
            val = 0;
            goto out;
        }
    }

out:
    spin_unlock_irqrestore(&mc->lock, flags);
    printk(KERN_ERR "*********remove: Released lock *************\n");
    return val;
}

asmlinkage long async(void *arg)
{
    int val = -EINVAL;
    struct async_data *buf = NULL;
    
    
    buf = kmalloc(sizeof(struct async_data),GFP_KERNEL);
    if(buf==NULL)
    {
    	val=-ENOMEM;
    	goto out;
    }
    
    if((val=validate_args(arg,buf))<0)
    {
    	goto out;
    }

    /* File permission check */
    if(buf->opflag ==0 || buf->opflag == 1 || buf->opflag == 4)
    {
        if((val=check_permissions(arg,buf))<0)
        {
            goto out;
        }
    }

    /* decryption work */
    if(buf->opflag ==0 || buf->opflag == 1)
    {
        val = encryption_work_producer(buf);
    }
    else if(buf->opflag == 2)
    {
        printk(KERN_ERR "Listing needs to be done: Requested elements: %d\n", buf->buff_length);
        val = list_jobs(buf);
        if(val == 0)
        {
            if(copy_to_user(arg, buf, sizeof(struct async_data)) == 0)
            {
                printk(KERN_ERR "Listed to the user\n");
            }
        }
        /* copy_to_user */
    }
    else if(buf->opflag == 3)
    {
        val = remove_job(buf);
        if(val == 0)
        {
            printk(KERN_ERR "Removed job\n");
        }
    }
    else if(buf->opflag ==4)
    {
        val = checksum_work_producer(buf);
    }

out:
    return val;
}


/* default functions for a moduler */
static int __init init_sys_async(void)
{
    int r = 0;
    printk("installed new sys_async module\n");
    if (sysptr == NULL)
        sysptr = async;
    
    r = create_work_queue();
    if(r < 0)
        goto out;
    
    /* create super struct */
    mc = kmalloc(sizeof(struct main_container), GFP_KERNEL);
    if(mc == NULL)
    {
        r = -ENOMEM;
        goto out;
    }
    
    /* initailize different things in mc */
    /* TODO: we might have to destroy them too */
    INIT_WORK(&mc->encryption_work, encryption_work);
    INIT_LIST_HEAD(&mc->pending_encryptions);
    mc->encrypt_len=0;
    
    INIT_LIST_HEAD(&mc->sleeping_encryptions);
    mc->sleeping_encrypt_len = 0;
    //global_job_number = 0;
    
    
out:
    return r;
}
static void  __exit exit_sys_async(void)
{
    if (sysptr != NULL)
        sysptr = NULL;
    printk("removed sys_async module\n");
    
    destroy_work_queue();
    
    kfree(mc);
}
module_init(init_sys_async);
module_exit(exit_sys_async);
MODULE_LICENSE("GPL");

