#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <openssl/md5.h>
#include "async_data.h"
#include <signal.h>

#define __NR_async	349	/* our private syscall number */
#define SIG_TEST 44

//char md5_buff[32];



/* main struct containing all different flags for agrument handling */
struct arguments
{
    int d_given;
    int e_given;
    int c_given;
    int p_given;
    int h_given;
    
};


void receiveData(int n, siginfo_t *info, void *unused)
{
    printf("Done: Finished Job_number: %d\tError: %d\n", info->si_errno, info->si_band);
    //printf("The buff is %s\n", md5_buff);	
    return;
}
/*
 * Main function: it collects the arguments passed by the user, send them to sys_xcrypt kernel module and
 * then returns the value returned by the sys_call.
 */
int main(int argc, char *argv[])
{
    struct sigaction sig;
    sig.sa_sigaction = receiveData;
    sig.sa_flags = SA_SIGINFO;
    sigaction(SIG_TEST, &sig, NULL);

    /* Necessary structs */
    struct arguments * args = malloc(sizeof(struct arguments));
    if(args == NULL)
    {
        fprintf(stderr, "Error: Error in allocating memory!\n");
        exit(1);
    }
    
    /* getopt's result will get into this */
    int getoptResult;
	int rc;
    int i = 0;    
    struct async_data *args_tobe_passed = malloc(sizeof(struct async_data));
    if(args_tobe_passed == NULL)
    {
        fprintf(stderr, "Error: Error in allocating memory!\n");
        exit(1);
    }
    args_tobe_passed->filename=malloc(FILENAME_LEN);
    args_tobe_passed->out_filename=malloc(FILENAME_LEN);
    args_tobe_passed->key=malloc(SIZE_OF_KEY_BUFFER + 1);
    /* Make sure the buffers are null to begin with */
    if(memset(args_tobe_passed->filename, '\0', FILENAME_LEN)==NULL)
    {
        fprintf(stderr, "Error: Error in cleaning up the buffers!\n");
        exit(1);
    }
    if(memset(args_tobe_passed->out_filename, '\0', FILENAME_LEN)==NULL)
    {
        fprintf(stderr, "Error: Error in cleaning up the buffers!\n");
        exit(1);
    }
    if(memset(args_tobe_passed->key, '\0', (SIZE_OF_KEY_BUFFER+1))==NULL)
    {
        fprintf(stderr, "Error: Error in cleaning up the buffers!\n");
        exit(1);
    }
    
    char *storePassword = malloc(SIZE_OF_KEY_BUFFER + 1);
    if(storePassword == NULL)
    {
        fprintf(stderr, "Error: Error in allocating memory!\n");
        exit(1);
    }
    
    char *correct_password = malloc(SIZE_OF_KEY_BUFFER);
    if(correct_password == NULL)
    {
        fprintf(stderr, "Error: Error in allocating memory!\n");
        exit(1);
    }
    
    int password_length_after_nullchar = 0;
    
    char *hashed_password = malloc(SIZE_OF_KEY_BUFFER);
    if(hashed_password == NULL)
    {
        fprintf(stderr, "Error: Error in allocating memory!\n");
        exit(1);
    }
    
    /* setting initial values */
    args->d_given = 0;
    args->e_given = 0;
    args->h_given = 0;
    args->p_given = 0;
    args->c_given = 0;
    /* Using getopt() */
    while((getoptResult = getopt(argc, argv, "dechp:")) != -1)
        switch(getoptResult)
    {
        case 'd':
        {
            args->d_given = 1;
            break;
        }
        case 'e':
        {
            args->e_given = 1;
            break;
        }
        case 'c':
        {
            args->c_given = 1;
	        args->p_given=1;
            break;
        }
        case 'h':
        {
            args->h_given = 1;
            break;
        }
        case 'p':
        {
            args->p_given = 1;
            /* Extra helper string for addtional padding to the user key if < 16 */
            char * hash_array = {"!)@(#*$&%^"};
            if(strlen(optarg) < 6)
            {
                fprintf(stderr, "Error: Length of the key (password) can't be less than 6.\n");
                exit(1);
            }
            else if(strlen(optarg)> 16)
            {
                fprintf(stderr, "Error: Length of the key (password) can't be more than 16.\n");
                exit(1);
            }
            
            if(strcpy(storePassword, optarg) == NULL)
            {
                fprintf(stderr, "Error: in retrieving your password\n");
                exit(1);
            }
            
            /* let's remove any new line characters in the password */
            i=0;
            while(storePassword[i])
            {
                if(storePassword[i] != '\0')
                {
                    correct_password[password_length_after_nullchar] = storePassword[i];
                    password_length_after_nullchar++;
                }
                i++;
            }
            correct_password[password_length_after_nullchar] = '\0';
            /* add extra padding */
            if(strlen(correct_password) < (SIZE_OF_KEY_BUFFER))
            {
                int l = 0;
                for(i=password_length_after_nullchar; i<SIZE_OF_KEY_BUFFER; i++)
                {
                    correct_password[password_length_after_nullchar] = hash_array[l];
                    l++;
                    password_length_after_nullchar++;
                }
            }
            /* Let's hash */
            MD5((unsigned char *)correct_password, SIZE_OF_KEY_BUFFER, (unsigned char *)hashed_password);
            /* Let's copy the string into struct */
            strncpy(args_tobe_passed->key, hashed_password, (SIZE_OF_KEY_BUFFER));
            args_tobe_passed->keylen = (int)strlen(args_tobe_passed->key);
            break;
        }
        case '?':
        {
            fprintf(stderr, "Supported Options are: [-deh] [-p PASSWD] infile outfile\nd -- decrypt\ne -- encrypt\nh -- help\n");
            exit(1);
            break;
        }
        default:
            break;
    }

    
    /* if the -h option is given */
    if(args->h_given == 1)
    {
        fprintf(stderr, "./xcipher [-deh] [-p PASSWD] infile outfile\nd -- decrypt\ne -- encrypt\nh -- help\n");
        exit(0);
    }
    
    /* too few arguments */
    if(argc < 4 && args->c_given == 1)
    {
        fprintf(stderr, "Error: Too few arguments.\n");
        exit(1);
    }
    else if(argc < 6 && args->c_given ==0)
    {
        fprintf(stderr, "Error: Too few arguments.\n");
        exit(1);
    }

    /* Too many aguments */
    else if(argc > 6)
    {
        fprintf(stderr, "Error: Too many arguments.\n");
        exit(1);
    }
    /* no password */
    else if(args->p_given == 0)
    {
        fprintf(stderr, "Error: No password was provided.\n");
        exit(1);
    }
    /* Various error checking combinations */
    // else if(args->e_given !=1 && args->d_given !=1)
    // {
    //     fprintf(stderr, "Error: No encryption or decryption option is found.\nPlease provide the option to encypt (-e) or to decrypt (-d), but not both.\n");
    //     exit(1);
    // }
    else if ((argc - optind) <1)
    {
        fprintf(stderr, "Error: Either input file or output file is missing\n");
        exit(1);
    }
    else if(args->e_given ==1 && args->d_given ==1)
    {
        fprintf(stderr, "Error: Either Encyption (-e) or Decyption (-d) option should be provided!, not both.\n");
        exit(1);
    }
    
    
    if(strncpy(args_tobe_passed->filename, argv[optind], strlen(argv[optind]))==NULL)
    {
        fprintf(stderr, "Error: Error occured while packing the arguments to the kernel.\n");
        exit(1);
    }
    if(strncpy(args_tobe_passed->out_filename, argv[optind+1], strlen(argv[optind+1]))==NULL)
    {
        fprintf(stderr, "Error: Error occured while packing the arguments to the kernel.\n");
        exit(1);
    }
    
    /* set proper encryption and decryption flag */
    if(args->e_given == 1)
    {
        //args_tobe_passed->eflag = 1;
        args_tobe_passed->opflag = 1; 
        args_tobe_passed->algo_name = CBC_AES;
    }
    else if(args->d_given == 1)
    {
        //args_tobe_passed->eflag = 0;
        args_tobe_passed->opflag = 0; 
        args_tobe_passed->algo_name = CBC_AES;
    }
    else if(args->c_given == 1)
    {
        args_tobe_passed->opflag = 4; 
        args_tobe_passed->algo_name = MD_5;
    }
    args_tobe_passed->pid=getpid();
    /* en/de cryption work */

    //memset(&md5_buff, '\n', 32);
    //strcpy(md5_buff,"testststs\0");	

    //args_tobe_passed->md5_user_buff= &md5_buff;    
    for(i =0 ; i< 1; i++)
    {
        args_tobe_passed->job_number = i;
      	rc = syscall(__NR_async, (void *) args_tobe_passed);
    	if (rc == 0)
    		printf("syscall executed successfully without any errors!\n");
    	else
    		printf("syscall returned error: %d (errno=%d)\n", rc, errno);

    }

   

    /*free memory */
    free(args);
    free(args_tobe_passed);
    free(storePassword);
    free(correct_password);
    free(hashed_password);
    //free(ad);
	exit(rc);
}

