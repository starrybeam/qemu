
#ifndef YBD_H
#define YBD_H
#ifdef __cplusplus
extern "C"{
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/cdefs.h>
#include <dirent.h>
#include <sys/statvfs.h>
#include <stdint.h>


struct yfs;
struct yfs_fd;
struct statfs; 

struct yfs* yfs_new(void);

int yfs_set_volfile_server(struct yfs* yfs, 
        const char* uuid,
        const char* localaddr,
        const char* localport,
        const char* monaddrs,
        const char* user,
        const char* sexport,
        const char* mmt,
        const char* transport);

int yfs_set_logging(struct yfs* yfs, unsigned short level);


int yfs_init(struct yfs* yfs);

void yfs_fini(struct yfs* yfs);

struct yfs_fd* yfs_open(struct yfs* yfs, const char* img, int flags);

int yfs_close(struct yfs_fd* fd);


#ifdef CONFIG_YFS_ZEROFILL
int yfs_zerofill_async(struct yfs_fd* fd, 
        off_t offset, 
        off_t size, 
        void (*finish_aiocb)(struct yfs_fd* fd, ssize_t ret, void *arg),
        void* acb);

int yfs_zerofill(struct yfs_fd* fd, off_t offset, off_t size);

#endif

struct yfs_fd* yfs_creat(struct yfs* yfs, 
        const char* image,
        int flags,
        unsigned short mode);

int yfs_remove(struct yfs* yfs, const char* image);


int yfs_ftruncate(struct yfs_fd* yfs, int64_t total_size);


int yfs_pwritev_async(struct yfs_fd* fd, 
        struct iovec *iov,
        int niov, 
        off_t offset,
        int unknown,
        void (*finish_aiocb)(struct yfs_fd* fd, ssize_t ret, void *arg),
        void* acb);

int yfs_preadv_async(struct yfs_fd* fd, 
        struct iovec *iov,
        int niov, 
        off_t offset,
        int unknown,
        void (*finish_aiocb)(struct yfs_fd* fd, ssize_t ret, void *arg),
        void* acb);

int yfs_fsync_async(struct yfs_fd* fd,
        void (*finish_aiocb)(struct yfs_fd* fd, ssize_t ret, void *arg),
        void* acb);


#ifdef CONFIG_YFS_DISCARD
int yfs_discard_async(struct yfs_fd* fd,
        off_t offset,
        off_t size,
        void (*finish_aiocb)(struct yfs_fd* fd, ssize_t ret, void *arg),
        void* acb);
#endif

off_t yfs_lseek(struct yfs_fd* fd, off_t offset, int whence);


int yfs_fstat(struct yfs_fd* fd, struct stat *st);

struct yfs_snap_info_t
{
    char id_str[128]; /* unique snapshot id */
    /* the following fields are informative. They are not needed for
     *        the consistency of the snapshot */
    char name[256]; /* user chosen name */
    uint64_t vm_state_size; /* VM state info size */
    uint32_t date_sec; /* UTC date of the snapshot */
    uint32_t date_nsec;
    uint64_t vm_clock_nsec; /* VM clock relative to boot */
};

const int YBD_MAX_SNAPS = 1000;

int yfs_snap_create(struct yfs_fd* fd, const char* snapname);

int yfs_snap_remove(struct yfs_fd* fd, const char* snapname);

int yfs_snap_rollback(struct yfs_fd* fd, const char* snapname);

int yfs_snap_list(struct yfs_fd* fd, struct yfs_snap_info_t *list, int *maxcount);

int yfs_clone(struct yfs* yfs, const char* img, const char* snap, const char* trg);

int yfs_statfs(struct yfs* yfs, const char* pool, struct statfs *buf);
#ifdef __cplusplus
}
#endif

#endif

