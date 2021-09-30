#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <error.h>
#include <errno.h>
#include <sys/mman.h>
#include <fcntl.h>
#define SYS_memfd_secret 447

static int memfd_secret(unsigned int flags)
{
    return syscall(SYS_memfd_secret, flags);
}

int main(){
    printf("Process ID %d\n",getpid());
    // declare data we want to keep 'secret'
    static const unsigned char data[] = "#!/bin/bash\nsleep 10;echo test";
    static const size_t dataSz = sizeof(data);
    // get file descriptor to anonymous 'secret' memory
    int ptrSecretMemory = memfd_secret(0);
    if (ptrSecretMemory == -1){
        printf("Failed -> %s\n",strerror(errno));
        return 1;
    }
    printf("Got fd to secret memory! -> %d\n",ptrSecretMemory);
    // make it match the size of our payload
    int truncateResult = ftruncate(ptrSecretMemory,dataSz);
    if (truncateResult < 0){
        printf("Failed to truncate memory chunk -> %s\n",strerror(errno));
        close(ptrSecretMemory);
        return 1;
    }
    // map the secret memory chunk into our process
    void *mappedMem;
    mappedMem = mmap(NULL,dataSz, PROT_READ | PROT_WRITE , MAP_SHARED, ptrSecretMemory ,0);
    if (mappedMem == MAP_FAILED){
        printf("Failed to map memmory into process -> %s\n",strerror(errno));
        close(ptrSecretMemory);
        return 1;
    }
    // copy the data into the secret memory chunk
    strncpy(mappedMem,data,dataSz);
    printf("Copied %zu bytes to secret memory %p\n",dataSz,mappedMem);
    /* 
     * You would do stuff with the memory here, but what you can do is limited 
     * there doesnt seem to be a way to make the memory executable, or
     * execute the file descriptor returned from memfd_secret
     * in poc.py i show a possible solution, 
     * copy the data from the secret memory and move it to an anonymous block
     * made by memfd_create another syscall that we can use to execute and ELF in memory.
     */
    munmap(mappedMem,dataSz);
    printf("Freed memory!\n");
    close(ptrSecretMemory);
    printf("Done!\n");
}

