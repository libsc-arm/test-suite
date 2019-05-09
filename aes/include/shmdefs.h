#ifndef SHMDEFS_H
#define SHMDEFS_H

#define PERM_FILE (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) // Permission bits
#define SHM_NAME "guineapig"
#define MAXSZ (8 * 1024)
#define END_MSG "end"

#define CID 0
#define SID 1024


struct shm_msg {
    int status;
    size_t len;
    char msg[MAXSZ];
};

#endif
