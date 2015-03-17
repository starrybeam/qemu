
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


struct yfs;
struct yfs_fd;


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

#ifdef __cplusplus
}
#endif

#endif

