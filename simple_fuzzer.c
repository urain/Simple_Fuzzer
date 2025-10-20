// Simple syscall fuzzer. Should be wrapped in a script to autolaunch on exit.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <execinfo.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/syscall.h>
 
pthread_mutex_t done = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond  = PTHREAD_COND_INITIALIZER;
pthread_t FUZZ_THREAD_ID;
pthread_t CHECKIN_THREAD_ID;
pthread_t MAIN_THREAD_ID;
int MAIN_PID;
uint64_t MAIN_THREAD_CHECKIN;
const char *FUZZ_INPUT_CONFIG = "fuzz_config.dat";

const uint64_t MAX_NUM_SYSCALLS = 529;
const uint64_t MAX_NUM_ARGS     = 12;

struct fuzz_input{
    uint64_t syscall_num;
    uint64_t num_args;
    uint64_t failed;
    uint64_t succeeded;
    uint64_t blacklist[MAX_NUM_SYSCALLS];
    uint64_t args[MAX_NUM_ARGS];
};

struct fuzz_input *FUZZ_INPUT;
uint64_t FUZZ_INPUT_SZ = sizeof(struct fuzz_input);
uint64_t BLACKLIST_SZ  = sizeof(FUZZ_INPUT->blacklist);
uint64_t ARGS_SZ       = sizeof(FUZZ_INPUT->args);


void protect_fuzz_input(void){
    mprotect(FUZZ_INPUT, FUZZ_INPUT_SZ, PROT_READ);
}

void unprotect_fuzz_input(void){
    mprotect(FUZZ_INPUT, FUZZ_INPUT_SZ, PROT_READ|PROT_WRITE);
}

void kill_all(void){
    
    printf("\nKilling All\n");
    
    unprotect_fuzz_input();
    
    FUZZ_INPUT->blacklist[FUZZ_INPUT->syscall_num] += 1;
    
    FILE *fp = fopen("fuzz_config.dat", "wb");
    fwrite(FUZZ_INPUT, FUZZ_INPUT_SZ, 1, fp);
    fclose(fp);
    
    pthread_kill(FUZZ_THREAD_ID, SIGUSR1);
    pthread_kill(MAIN_THREAD_ID, SIGUSR1);
    kill(MAIN_PID, SIGUSR1);
    
    sleep(10);
    exit(0);
}


void myCheckinThread(void){
    int fail = 0;
    while( fail < 10 ){
        if(MAIN_THREAD_CHECKIN == 1){
            MAIN_THREAD_CHECKIN = 0;
            fail = 0;
        }
        else{
            fail += 1;
            printf("\nMAIN CHECKIN FAILED: %d\n", fail);
        }
        sleep(1);
    }
    // main thread failed to checkin in time
    kill_all();
}
 
void mySyscallThread(void){
    
    printf("\nSYSCALL TEST: %lld\n", FUZZ_INPUT->syscall_num);
    for (int i = 0; i < MAX_NUM_ARGS; i++){
        printf("    %2d: 0x%llx\n", i, FUZZ_INPUT->args[i]);
    }
    
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wdeprecated-declarations"
    syscall(
        (int)FUZZ_INPUT->syscall_num,
        FUZZ_INPUT->args[0],
        FUZZ_INPUT->args[1],
        FUZZ_INPUT->args[2],
        FUZZ_INPUT->args[3],
        FUZZ_INPUT->args[4],
        FUZZ_INPUT->args[5],
        FUZZ_INPUT->args[6],
        FUZZ_INPUT->args[7],
        FUZZ_INPUT->args[8],
        FUZZ_INPUT->args[9],
        FUZZ_INPUT->args[10],
        FUZZ_INPUT->args[11]
    );
    #pragma clang diagnostic pop
    
    pthread_cond_signal(&cond);
    return;
}
 
 
void sig_handler(int signo)
{
    printf("\nSIGHANDLER HIT: %d  %s\n", signo, strerror(signo));

    switch(signo){
        case SIGSYS:
        case SIGABRT:
        case SIGSEGV:
        case SIGILL:
        case SIGBUS:
            kill_all();
            sleep(10);
            exit(0);
        case SIGUSR2:  // we use SIGUSR2 to kill the fuzz thread
        default:
            break;
    }
    unprotect_fuzz_input();
    FUZZ_INPUT->blacklist[FUZZ_INPUT->syscall_num] += 1;
    return;
}

// Blacklist calls we know will cause issues or fail
void pre_blacklist(void){
    FUZZ_INPUT->blacklist[37]  = 0xff;
    FUZZ_INPUT->blacklist[55]  = 0xff;
    FUZZ_INPUT->blacklist[66]  = 0xff;
    FUZZ_INPUT->blacklist[73]  = 0xff;
    FUZZ_INPUT->blacklist[111] = 0xff;
    FUZZ_INPUT->blacklist[126] = 0xff;
    FUZZ_INPUT->blacklist[134] = 0xff;
    FUZZ_INPUT->blacklist[183] = 0xff;
    FUZZ_INPUT->blacklist[244] = 0xff;
    FUZZ_INPUT->blacklist[361] = 0xff;
    FUZZ_INPUT->blacklist[380] = 0xff;
    FUZZ_INPUT->blacklist[433] = 0xff;
    FUZZ_INPUT->blacklist[434] = 0xff;
    FUZZ_INPUT->blacklist[435] = 0xff;
    FUZZ_INPUT->blacklist[520] = 0xff;
    FUZZ_INPUT->blacklist[521] = 0xff;
}


int main(int argc, const char * argv[]) {
    
    /* Shared memory option if you want to fork instead of thread.
    int KEY = 27;
    shm_unlink(KEY);
    int sharedMemId = shmget(KEY, FUZZ_INPUT_SZ, IPC_CREAT | 0666);
    if (sharedMemId < 0){
        printf("Could Not Setup Shared Memory\n");
        return 0;
    }
    FUZZ_INPUT = shmat(sharedMemId, NULL, 0);
    if (FUZZ_INPUT <= 0){
        printf("Could Not Map In Shared Memory\n");
        return 0;
    }
    */
    
    FUZZ_INPUT = mmap(0,
                      FUZZ_INPUT_SZ,
                      PROT_READ | PROT_WRITE,
                      MAP_ANONYMOUS | MAP_PRIVATE , -1, 0);
    
    // Create our fuzz_config file if it doesn't already exist
    // or read it if it does exist
    FILE *fp = fopen("fuzz_config.dat", "a");
    fclose(fp);
    fp = fopen("fuzz_config.dat", "rb");
    fread(FUZZ_INPUT, FUZZ_INPUT_SZ, 1, fp);
    fclose(fp);
    
    // Blacklist syscalls we know will fail or cause issues
    pre_blacklist();

    // Setup signal handlers to catch exceptions
    signal(SIGSYS,  sig_handler);
    signal(SIGABRT, sig_handler);
    signal(SIGSEGV, sig_handler);
    signal(SIGILL,  sig_handler);
    signal(SIGBUS,  sig_handler);
    signal(SIGUSR2, sig_handler); // We use SIGUSR2 to kill fuzz thread
    
    // Get our main thread id and pid
    MAIN_PID = getpid();
    MAIN_THREAD_ID = pthread_self();
    
    // Spin up a thread that will check if the main thrad hang
    pthread_create(&CHECKIN_THREAD_ID, 0, (void*)myCheckinThread, 0);
        
    uint64_t runs = 0;
    
    while(1){
        // checkin with the main thread checker to say we're not hung up.
        MAIN_THREAD_CHECKIN = 1;
                
        if ( runs % 500 == 0 ){
            printf("\n\nBLACKLIST:\n");
            for ( int i = 0; i < MAX_NUM_SYSCALLS; i++){
                if (i % 16 == 0 && i != 0){
                    printf("\n");
                }
                uint8_t blacklisted = (uint8_t)FUZZ_INPUT->blacklist[i];
                if (blacklisted == 0)
                    printf("%03d: %2s  ",i," ");
                else
                    printf("%03d: %02x  ",i, (uint8_t)FUZZ_INPUT->blacklist[i]);
            }
            printf("\n");
            printf("LASTCALL:    %llu\n",FUZZ_INPUT->syscall_num);
            printf("SUCCEEDED:   %llu\n",FUZZ_INPUT->succeeded);
            printf("FAILED:      %llu\n",FUZZ_INPUT->failed);
            fflush(stdout);
        }
        
        // choose random syscall that isn't blacklisted
        while(1){
            FUZZ_INPUT->syscall_num = (arc4random() % MAX_NUM_SYSCALLS);
            if (FUZZ_INPUT->blacklist[FUZZ_INPUT->syscall_num] <= 0x5)
                break;
            else
                FUZZ_INPUT->blacklist[FUZZ_INPUT->syscall_num] = 0xff;
        }
        
        // Choose args
        arc4random_buf(FUZZ_INPUT->args, ARGS_SZ);

        printf("FUZZ_INPUT->syscall_num: %lld\n", FUZZ_INPUT->syscall_num);
        // backup fuzz config data
        FILE *fptr;
        fptr = fopen("fuzz_config.dat","w");
        fwrite(FUZZ_INPUT, FUZZ_INPUT_SZ, 1, fptr);
        fclose(fptr);
                
        // Protect FUZZ_INPUT with READ ONLY to avoid the fuzzer messing with it
        protect_fuzz_input();
        
        // create the syscall thread
        pthread_create(&FUZZ_THREAD_ID, 0, (void*)mySyscallThread, 0);
        
        // Start the timer to wait for thread
        int rc;
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 5;
        ts.tv_nsec += 0;
        
        // Lock the mutex
        pthread_mutex_lock(&done);
        rc = pthread_cond_timedwait(&cond, &done, &ts);
        pthread_mutex_unlock(&done);
        
        // Fuzz thread should be done now so we can unprotect FUZZ_INPUT
        unprotect_fuzz_input();
        
        // Check timeout condition
        if ( rc == ETIMEDOUT ){
            printf("\nTIMED OUT SYSCALL: %lld    TIMES: %lld\n",
                   FUZZ_INPUT->syscall_num,
                   FUZZ_INPUT->blacklist[FUZZ_INPUT->syscall_num]
                   );
            FUZZ_INPUT->blacklist[FUZZ_INPUT->syscall_num] += 1;
            FUZZ_INPUT->failed += 1;
            pthread_kill(FUZZ_THREAD_ID, SIGUSR2);
        }
        else {
            FUZZ_INPUT->blacklist[FUZZ_INPUT->syscall_num] = 0;
            FUZZ_INPUT->succeeded += 1;
        }
        runs += 1;
    }
    
    return 0;
}
