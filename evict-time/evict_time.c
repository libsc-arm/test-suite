#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <emmintrin.h>
#include <x86intrin.h>

#include "libflush.h"

#define REPEAT 5


void write(volatile int *ptr) {
		for (int i = 0; i < REPEAT; ++i) { 
			*(ptr + i) = i + 1; 
		} 
}

void timeit(struct libflush_session_t *session, void *ptr) {
    uint64_t time = libflush_flush_time(session, ptr);
    printf("%lu\n", time);
}

void flush(struct libflush_session_t *session, void *ptr) {
    for(int i = 0; i < REPEAT; i++) {
        libflush_flush(session, ptr); 
    }
}
 
int main() 
{ 
    void *ptr; 
	// volatile int n, i, sum = 0,start,end; 
    struct libflush_session_t *session;
    libflush_init(&session, NULL);
	ptr = calloc(1000, 64);  
    write(ptr); 
    timeit(session, ptr); 
    flush(session, ptr);
    timeit(session, ptr);
    libflush_terminate(session);
	return 0; 
}
