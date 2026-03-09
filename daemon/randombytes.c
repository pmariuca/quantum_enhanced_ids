// Userspace RNG for PQClean
#include <stdint.h>
#include <stddef.h>
#include <sys/random.h>
#include <unistd.h>
#include <fcntl.h>

static void rng_fill(uint8_t *out, size_t outlen){
    size_t done=0;
    while(done<outlen){
        ssize_t r=getrandom(out+done,outlen-done,0);
        if(r>0){ done+= (size_t)r; continue; }
        int fd=open("/dev/urandom",O_RDONLY);
        if(fd>=0){ while(done<outlen){ r=read(fd,out+done,outlen-done); if(r<=0)break; done+=(size_t)r; } close(fd); }
        break;
    }
}
void randombytes(uint8_t *o, size_t n){ rng_fill(o,n); }
void PQCLEAN_randombytes(uint8_t *o, size_t n){ rng_fill(o,n); }
void PQCLEAN_MLDSA44_CLEAN_randombytes(uint8_t *o, size_t n){ rng_fill(o,n); }