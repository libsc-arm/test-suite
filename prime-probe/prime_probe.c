#include <sys/mman.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <x86intrin.h>

#include "libflush.h"

#define _USE_MATH_DEFINES

#define L1_ASSOC 8
#define L1_CACHELINE 64
#define L1_STRIDE (L1_ASSOC * L1_CACHELINE)
#define L1_SETS 64
#define LVAL(ptr) (*(void **)(ptr))


unsigned l1 = 0, l2 = 0, l3 = 0, mem_access = 0;
struct libflush_session_t *session;

static inline double _log2(const double n) {
    return log(n) * M_LOG2E;
}

void* get_ptr(void *addr, uint32_t set, uint32_t way, uint32_t ptr) {
    return (void *)(((uintptr_t) addr) + ((set) * L1_CACHELINE) + ((way) * L1_STRIDE) + ((ptr * sizeof(void *))));
}

static void probelist(void *p, int segments, int seglen, uint16_t *results) {
  while (segments--) {
    uint64_t start = libflush_get_timing_start(session);
    for (int i = seglen; i--; ) {
      libflush_access_memory(p);
      p = LVAL(p);
    }
    uint64_t end = libflush_get_timing_end(session) - start;
    printf("Addr %p - %lu ticks\n",(uint64_t *)p, end / seglen);

    if (end / seglen < 10) {
        ++l2;
    } else if (end / seglen < 60) {
        ++l3;
    } else {
        ++mem_access;
    }
    results++;
  }
}

struct page_params {
    uint32_t page_size;
    uint32_t offset;
    uint32_t phy_page_num_size;
};

struct node {
    void *addr;
    void *fwdlist;
    void *bkwlist;
    uint8_t monitored[L1_SETS];
    int nsets;
};

void set_params(struct page_params *pp) {
    uint32_t page_size = getpagesize();
    uint32_t page_offset = _log2(page_size);
    pp->page_size = page_size;
    pp->offset = page_offset;
    pp->phy_page_num_size = page_size - page_offset;
}

void init_node(struct node *n) {
    n->fwdlist = NULL;
    n->bkwlist = NULL;
    n->nsets = L1_SETS;
}

void __alloc(void *virt_addr) {
    
    for (int i = 0; i < L1_SETS; i++) {
        for (int j = 0; j < L1_ASSOC - 1; j++) {
            LVAL(get_ptr(virt_addr, i, j, 0)) = (get_ptr(virt_addr, i, j + 1, 0));
            LVAL(get_ptr(virt_addr, i, j + 1, 1)) = (get_ptr(virt_addr, i, j, 1));
            //printf("%p\n", (uint64_t *) virt_addr);
        }
    }
}

static void rebuild(struct node *n) {
    for (int i = 0; i < n->nsets - 1; i++) {
        LVAL(get_ptr(n->addr, n->monitored[i], L1_ASSOC - 1, 0)) = get_ptr(n->addr, n->monitored[i+1], 0, 0);
        LVAL(get_ptr(n->addr, n->monitored[i], 0, 1)) = get_ptr(n->addr, n->monitored[i+1], L1_ASSOC - 1, 1);
    }
    
    n->fwdlist = LVAL(get_ptr(n->addr, n->monitored[n->nsets - 1], L1_ASSOC - 1, 0)) = get_ptr(n->addr, n->monitored[0], 0, 0);
    n->bkwlist = LVAL(get_ptr(n->addr, n->monitored[n->nsets - 1], 0, 1)) = get_ptr(n->addr, n->monitored[0], L1_ASSOC - 1, 1);

    //printf("%u\n%p\n%p", (uint8_t) n->monitored[n->nsets - 1], (uint64_t *) n->fwdlist, (uint64_t *) n->bkwlist);
}


static void randomise(struct node *n) {
    for (int i = 0; i < n->nsets; i++) {
        int p = random() % (n->nsets - i) + i;
        uint8_t t = n->monitored[p];
        n->monitored[p] = n->monitored[i];
        n->monitored[i] = t;
  }
  rebuild(n);
}

void monitor(struct node *n) {
    for (int i = 0; i < L1_SETS; i++)
        n->monitored[i] = i;

    randomise(n);
}

void probe(struct node *n, uint16_t *results) {
  probelist(n->fwdlist, n->nsets, L1_ASSOC, results);
}

void bprobe(struct node * n, uint16_t *results) {
  probelist(n->bkwlist, n->nsets, L1_ASSOC, results);
}

int main() {
    
    libflush_init(&session, NULL);
    struct page_params *pp = malloc(sizeof(struct page_params));
    set_params(pp); 
   
    struct node *n = malloc(sizeof(struct node)); 
    n->addr = mmap(NULL, pp->page_size * L1_ASSOC, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANON, -1, 0);
    
    if (n->addr == MAP_FAILED)
        printf("Mmap failed to allocate memory %s\n", strerror(errno));
    else {
        init_node(n);
        __alloc(n->addr);
        monitor(n);
        uint16_t *results = malloc(sizeof(n->nsets * sizeof(uint16_t)));
        //printf("%s\n", "Forward probe");
        probe(n, results);

        //printf("\n%s\n", "Backward probe");
        bprobe(n, results);

        munmap(n->addr, pp->page_size * L1_ASSOC);
    }

    printf("%u %u", l3, mem_access);
    FILE *out;
    out = fopen("file.txt", "w");
    fprintf(out, "%u\n", l3);
    fprintf(out, "%u", mem_access);
    libflush_terminate(session);
    return 0;
}
