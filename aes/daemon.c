/* 
 * Security daemon mimics a server, it communicates with the
 * attacker through IPC
 */

#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "include/shmdefs.h"


int server_fd;
void *addr;

struct shm_msg *client_msg;
struct shm_msg *server_msg;

static unsigned char key[16] = {0x28, 0x10, 0x22, 0x32, 0x05, 0x53, 0x07,
    0x25, 0x19, 0x54, 0x11, 0x47, 0x13, 0x56, 0x15, 0x16};

unsigned char enc[16] = {0,};
unsigned char msg[MAXSZ] = {0,};

AES_KEY aes_key;

// Set AES key.
void set_aes_key() {
    if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
        perror("[server]: Failed to set encryption key");
    }
}

// AES encryption.
void aes_encrypt(unsigned char *in, unsigned char *out, const unsigned char *userKey) {
    AES_KEY aes_key;
    if (AES_set_encrypt_key(userKey, 128, &aes_key) < 0) {
        perror("[server]: Set encrypt key error");
        return;
    }
    AES_ecb_encrypt(in, out, &aes_key, AES_ENCRYPT);
}

// Predict result.
void predict_result() {
    unsigned real, cand, recovered;
    unsigned char *candidate_key;
    candidate_key = (unsigned char *)client_msg->msg + sizeof(END_MSG);
    recovered = 0;

    for (int i = 0; i < sizeof(key); i++) {
        real = (key[i] >> 4);
        cand = (candidate_key[i] >> 4);

        if ((real & (1 << 0)) == (cand & (1 << 0)))
            recovered++;
        if ((real & (1 << 1)) == (cand & (1 << 1)))
            recovered++;
        if ((real & (1 << 2)) == (cand & (1 << 2)))
            recovered++;
        if ((real & (1 << 3)) == (cand & (1 << 3)))
            recovered++;
    }
    printf("Key : ");
    for (int i = 0; i < sizeof(key); i++)
        printf("%02x", key[i]);
    printf("\n");

    printf("Predicted Key : ");
    for (int i = 0; i < sizeof(key); i++)
        printf("%02x", candidate_key[i]);
    printf("\n");
    printf("Recovered %d\n", recovered);
}


int main(int argc, char **argv) {
    // Open SHM.
    if ((server_fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, PERM_FILE)) == -1) {
        perror("[server]: Failed to open SHM");
    }

    // Truncate the file to the specified length.
    if (ftruncate(server_fd, MAXSZ) == -1) {
        perror("[server]: Ftruncate returned error");
        return -1;
    }

    // Map addr to the server file descriptor.
    addr = mmap(NULL, MAXSZ, PROT_READ | PROT_WRITE, MAP_SHARED, server_fd, 0);

    if (addr == MAP_FAILED) {
        perror("Mmap error");
        return -1;
    }

    memset(addr, 0, MAXSZ);
    client_msg = (struct shm_msg *)((char *)addr + CID);
    server_msg = (struct shm_msg *)((char *)addr + SID);

    printf("[server]: Starting ...\n");
    printf("[server]: Encryption key : ");
    for (int i = 0; i < sizeof(key); i++)
        printf("%02x", key[i]);
    printf("\n");

    /*
     * Message loop routine
     */

    while(1) {
        while(1) {
            if (client_msg->status == 1) {
                memcpy(msg, client_msg->msg, client_msg->len);
                client_msg->status = 0;
                break;
            }
            sleep(0);
        }

        if (client_msg->len == (sizeof(END_MSG) + sizeof(key))) {
            printf("[server]: End message\n");
            predict_result();
            break;
        }
        
        // Prepare message
        server_msg->status = 0;
        server_msg->len = sizeof(enc);

        // Encryption
        aes_encrypt(msg, enc, key);

        // Send encrypted message to client.
        memcpy(server_msg->msg, enc, server_msg->len);
        server_msg->status = 1;
    }

    printf("[server]: Daemon is closing \n");

    // Destroy mapping
    if (munmap(addr, MAXSZ) == -1) {
        perror("[server]: Munmap error");
    }

    // Close file descriptor.
    if (close(server_fd) == -1) {
        perror("[server]: Failed to close shm file descriptor");
    }
    
    // Unlink SHM
    if (shm_unlink(SHM_NAME) == -1) {
        perror("[server]: SHM unlink error");
    }

    return 0;
}
