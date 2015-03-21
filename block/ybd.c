/*
 * YeeStorFS backend for QEMU
 *
 * Copyright (C) 2012 Bharata B Rao <bharata@linux.vnet.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */
#include "block/block_int.h"
#include "qemu/uri.h"
#include "qemu/option_int.h"
#include "ybd.h"

#define YBD_OPT_CMD "cmd"
#define YBD_OPT_IMG "img"
#define YBD_OPT_TRG "trg"
#define YBD_OPT_SNP "snap"

#define YBD_CMD_DEL "del"
#define YBD_CMD_CLONE "clone"
#define YBD_ROOT "yfs:/root/root"

typedef struct YfsAIOCB {
    int64_t size;
    int ret;
    QEMUBH *bh;
    Coroutine *coroutine;
    AioContext *aio_context;
} YfsAIOCB;

typedef struct BDRVYfsState {
    struct yfs *yfs;
    struct yfs_fd *fd;
    bool isroot;
} BDRVYfsState;

typedef struct YfsConf {
    char *uuid;
    char *localaddr;
    char *localport;
    char *monaddrs;
    char *user;
    char *sexport;
    char *mnt;
    char *pool;
    char *image;
    char *transport;
} YfsConf;

static void qemu_yfs_gconf_free(YfsConf *gconf)
{
    if (gconf) {
        g_free(gconf->uuid);
        g_free(gconf->localaddr);
        g_free(gconf->localport);
        g_free(gconf->monaddrs);
        g_free(gconf->user);
        g_free(gconf->sexport);
        g_free(gconf->mnt);
        g_free(gconf->pool);
        g_free(gconf->image);
        g_free(gconf->transport);
        g_free(gconf);
    }
}

static int parse_volume_options(YfsConf *gconf, char *path)
{
    char *p, *q;

    if (!path) {
        return -EINVAL;
    }

    /* volume */
    p = q = path + strspn(path, "/");
    p += strcspn(p, "/");
    if (*p == '\0') {
        return -EINVAL;
    }
    gconf->pool = g_strndup(q, p - q);

    /* image */
    p += strspn(p, "/");
    if (*p == '\0') {
        return -EINVAL;
    }
    gconf->image = g_strdup(p);
    return 0;
}

/*
 * file=yfs[+transport]://[server[:port]]/volname/image[?socket=...]
 *
 * 'yfs' is the protocol.
 *
 * 'transport' specifies the transport type used to connect to yfs
 * management daemon (yfsd). Valid transport types are
 * tcp, unix and rdma. If a transport type isn't specified, then tcp
 * type is assumed.
 *
 * 'server' specifies the server where the volume file specification for
 * the given volume resides. This can be either hostname, ipv4 address
 * or ipv6 address. ipv6 address needs to be within square brackets [ ].
 * If transport type is 'unix', then 'server' field should not be specified.
 * The 'socket' field needs to be populated with the path to unix domain
 * socket.
 *
 * 'port' is the port number on which yfsd is listening. This is optional
 * and if not specified, QEMU will send 0 which will make yfs to use the
 * default port. If the transport type is unix, then 'port' should not be
 * specified.
 *
 * 'volname' is the name of the yfs volume which contains the VM image.
 *
 * 'image' is the path to the actual VM image that resides on yfs volume.
 *
 * Examples:
 *
 * file=yfs://1.2.3.4/testvol/a.img
 * file=yfs+tcp://1.2.3.4/testvol/a.img
 * file=yfs+tcp://1.2.3.4:24007/testvol/dir/a.img
 * file=yfs+tcp://[1:2:3:4:5:6:7:8]/testvol/dir/a.img
 * file=yfs+tcp://[1:2:3:4:5:6:7:8]:24007/testvol/dir/a.img
 * file=yfs+tcp://server.domain.com:24007/testvol/dir/a.img
 * file=yfs+unix:///testvol/dir/a.img?socket=/tmp/yfsd.socket
 * file=yfs+rdma://1.2.3.4:24007/testvol/a.img
 */
static int qemu_yfs_parseuri(YfsConf *gconf, const char *filename)
{
    URI *uri;
    QueryParams *qp = NULL;
    bool is_unix = false;
    int ret = 0;

    uri = uri_parse(filename);
    if (!uri) {
        return -EINVAL;
    }

    /* transport */
    if (!uri->scheme || !strcmp(uri->scheme, "yfs")) {
        gconf->transport = g_strdup("tcp");
    } else if (!strcmp(uri->scheme, "yfs+tcp")) {
        gconf->transport = g_strdup("tcp");
    } else if (!strcmp(uri->scheme, "yfs+unix")) {
        gconf->transport = g_strdup("unix");
        is_unix = true;
    } else if (!strcmp(uri->scheme, "yfs+rdma")) {
        gconf->transport = g_strdup("rdma");
    } else {
        ret = -EINVAL;
        goto out;
    }

    ret = parse_volume_options(gconf, uri->path);
    if (ret < 0) {
        goto out;
    }

    qp = query_params_parse(uri->query);
    if (qp->n > 1 || (is_unix && !qp->n) || (!is_unix && qp->n)) {
        ret = -EINVAL;
        goto out;
    }


out:
    if (qp) {
        query_params_free(qp);
    }
    uri_free(uri);
    return ret;
}

static struct yfs *qemu_yfs_init(YfsConf *gconf, const char *filename,
                                      Error **errp)
{
    struct yfs *yfs = NULL;
    int ret;
    int old_errno;

    ret = qemu_yfs_parseuri(gconf, filename);
    if (ret < 0) {
        error_setg(errp, "Usage: file=yfs[+transport]://[server[:port]]/"
                   "volname/image[?socket=...]");
        errno = -ret;
        goto out;
    }

    yfs = yfs_new();
    if (!yfs) {
        goto out;
    }

    ret = yfs_set_volfile_server(yfs, gconf->uuid, gconf->localaddr, gconf->localport, 
            gconf->monaddrs, gconf->user, gconf->sexport, gconf->mnt, gconf->transport);
    if (ret < 0) {
        goto out;
    }

    /*
     * TODO: Use GF_LOG_ERROR instead of hard code value of 4 here when
     * YfsFS makes GF_LOG_* macros available to libgfapi users.
     */
    ret = yfs_set_logging(yfs, 4);
    if (ret < 0) {
        goto out;
    }

    ret = yfs_init(yfs);
    if (ret) {
        error_setg_errno(errp, errno,
                         "Yfs connection failed for localaddr=%s port=%s "
                         "pool=%s image=%s transport=%s", gconf->localaddr,
                         gconf->localport, gconf->pool, gconf->image,
                         gconf->transport);

        /* yfs_init sometimes doesn't set errno although docs suggest that */
        if (errno == 0)
            errno = EINVAL;

        goto out;
    }
    return yfs;

out:
    if (yfs) {
        old_errno = errno;
        yfs_fini(yfs);
        errno = old_errno;
    }
    return NULL;
}

static void qemu_yfs_complete_aio(void *opaque)
{
    YfsAIOCB *acb = (YfsAIOCB *)opaque;

    qemu_bh_delete(acb->bh);
    acb->bh = NULL;
    qemu_coroutine_enter(acb->coroutine, NULL);
}

/*
 * AIO callback routine called from YfsFS thread.
 */
static void yfs_finish_aiocb(struct yfs_fd *fd, ssize_t ret, void *arg)
{
    YfsAIOCB *acb = (YfsAIOCB *)arg;

    if (!ret || ret == acb->size) {
        acb->ret = 0; /* Success */
    } else if (ret < 0) {
        acb->ret = ret; /* Read/Write failed */
    } else {
        acb->ret = -EIO; /* Partial read/write - fail it */
    }

    acb->bh = aio_bh_new(acb->aio_context, qemu_yfs_complete_aio, acb);
    qemu_bh_schedule(acb->bh);
}

/* TODO Convert to fine grained options */
static QemuOptsList runtime_opts = {
    .name = "yfs",
    .head = QTAILQ_HEAD_INITIALIZER(runtime_opts.head),
    .desc = {
        {
            .name = "filename",
            .type = QEMU_OPT_STRING,
            .help = "URL to the yfs image",
        },
        { /* end of list */ }
    },
};

static void qemu_yfs_parse_flags(int bdrv_flags, int *open_flags)
{
    assert(open_flags != NULL);

    *open_flags |= O_BINARY;

    if (bdrv_flags & BDRV_O_RDWR) {
        *open_flags |= O_RDWR;
    } else {
        *open_flags |= O_RDONLY;
    }

    if ((bdrv_flags & BDRV_O_NOCACHE)) {
        *open_flags |= O_DIRECT;
    }
}

static int qemu_yfs_open(BlockDriverState *bs,  QDict *options,
                             int bdrv_flags, Error **errp)
{
    BDRVYfsState *s = bs->opaque;
    int open_flags = 0;
    int ret = 0;
    YfsConf *gconf = g_new0(YfsConf, 1);
    QemuOpts *opts;
    Error *local_err = NULL;
    const char *filename;
    char path[4096];
    memset(path, 0, 4096);

    opts = qemu_opts_create(&runtime_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, options, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        ret = -EINVAL;
        goto out;
    }

    filename = qemu_opt_get(opts, "filename");


    s->yfs = qemu_yfs_init(gconf, filename, errp);
    if (!s->yfs) {
        ret = -errno;
        goto out;
    }

    qemu_yfs_parse_flags(bdrv_flags, &open_flags);

    if (!strcmp(filename, YBD_ROOT)) {
        s->isroot = true;
        goto out;
        
    }

    sprintf(path, "/%s/%s", gconf->pool, gconf->image);
    s->fd = yfs_open(s->yfs, path, open_flags);
    if (!s->fd) {
        ret = -errno;
    }

out:
    qemu_opts_del(opts);
    qemu_yfs_gconf_free(gconf);
    if (!ret) {
        return ret;
    }
    if (s->fd) {
        yfs_close(s->fd);
    }
    if (s->yfs) {
        yfs_fini(s->yfs);
    }
    return ret;
}

typedef struct BDRVYfsReopenState {
    struct yfs *yfs;
    struct yfs_fd *fd;
} BDRVYfsReopenState;


static int qemu_yfs_reopen_prepare(BDRVReopenState *state,
                                       BlockReopenQueue *queue, Error **errp)
{
    int ret = 0;
    BDRVYfsReopenState *reop_s;
    YfsConf *gconf = NULL;
    int open_flags = 0;
    char path[4096];
    memset(path, 0, 4096);

    assert(state != NULL);
    assert(state->bs != NULL);

    state->opaque = g_new0(BDRVYfsReopenState, 1);
    reop_s = state->opaque;

    qemu_yfs_parse_flags(state->flags, &open_flags);

    gconf = g_new0(YfsConf, 1);

    reop_s->yfs = qemu_yfs_init(gconf, state->bs->filename, errp);
    if (reop_s->yfs == NULL) {
        ret = -errno;
        goto exit;
    }

    if (!strcmp(state->bs->filename, YBD_ROOT)) {
        ret = 0;
        goto exit;
    }

    sprintf(path, "/%s/%s", gconf->pool, gconf->image);
    reop_s->fd = yfs_open(reop_s->yfs, path, open_flags);
    if (reop_s->fd == NULL) {
        /* reops->yfs will be cleaned up in _abort */
        ret = -errno;
        goto exit;
    }

exit:
    /* state->opaque will be freed in either the _abort or _commit */
    qemu_yfs_gconf_free(gconf);
    return ret;
}

static void qemu_yfs_reopen_commit(BDRVReopenState *state)
{
    BDRVYfsReopenState *reop_s = state->opaque;
    BDRVYfsState *s = state->bs->opaque;


    /* close the old */
    if (s->fd) {
        yfs_close(s->fd);
    }
    if (s->yfs) {
        yfs_fini(s->yfs);
    }

    /* use the newly opened image / connection */
    s->fd         = reop_s->fd;
    s->yfs       = reop_s->yfs;

    g_free(state->opaque);
    state->opaque = NULL;

    return;
}


static void qemu_yfs_reopen_abort(BDRVReopenState *state)
{
    BDRVYfsReopenState *reop_s = state->opaque;

    if (reop_s == NULL) {
        return;
    }

    if (reop_s->fd) {
        yfs_close(reop_s->fd);
    }

    if (reop_s->yfs) {
        yfs_fini(reop_s->yfs);
    }

    g_free(state->opaque);
    state->opaque = NULL;

    return;
}

#ifdef CONFIG_YFS_ZEROFILL
static coroutine_fn int qemu_yfs_co_write_zeroes(BlockDriverState *bs,
        int64_t sector_num, int nb_sectors, BdrvRequestFlags flags)
{
    int ret;
    YfsAIOCB *acb = g_slice_new(YfsAIOCB);
    BDRVYfsState *s = bs->opaque;
    off_t size = nb_sectors * BDRV_SECTOR_SIZE;
    off_t offset = sector_num * BDRV_SECTOR_SIZE;

    acb->size = size;
    acb->ret = 0;
    acb->coroutine = qemu_coroutine_self();
    acb->aio_context = bdrv_get_aio_context(bs);

    ret = yfs_zerofill_async(s->fd, offset, size, &yfs_finish_aiocb, acb);
    if (ret < 0) {
        ret = -errno;
        goto out;
    }

    qemu_coroutine_yield();
    ret = acb->ret;

out:
    g_slice_free(YfsAIOCB, acb);
    return ret;
}

static inline bool yfs_supports_zerofill(void)
{
    return 1;
}

static inline int qemu_yfs_zerofill(struct yfs_fd *fd, int64_t offset,
        int64_t size)
{
    return yfs_zerofill(fd, offset, size);
}

#else
static inline bool yfs_supports_zerofill(void)
{
    return 0;
}

static inline int qemu_yfs_zerofill(struct yfs_fd *fd, int64_t offset,
        int64_t size)
{
    return 0;
}
#endif

static int qemu_yfs_create(const char *filename,
                               QemuOpts *opts, Error **errp)
{
    struct yfs *yfs = NULL;
    struct yfs_fd *fd;
    int ret = 0;
    int prealloc = 0;
    int64_t total_size = 0;
    char *tmp = NULL;
    YfsConf *gconf = g_new0(YfsConf, 1);
    char path[4096];
    memset(path, 0, 4096);

    if (!strcmp(filename, YBD_ROOT)) {
        ret = -EEXIST;
        goto out;
    }

    yfs = qemu_yfs_init(gconf, filename, errp);
    if (!yfs) {
        ret = -errno;
        goto out;
    }

    total_size = ROUND_UP(qemu_opt_get_size_del(opts, BLOCK_OPT_SIZE, 0),
                          BDRV_SECTOR_SIZE);

    tmp = qemu_opt_get_del(opts, BLOCK_OPT_PREALLOC);
    if (!tmp || !strcmp(tmp, "off")) {
        prealloc = 0;
    } else if (!strcmp(tmp, "full") &&
               yfs_supports_zerofill()) {
        prealloc = 1;
    } else {
        error_setg(errp, "Invalid preallocation mode: '%s'"
            " or YfsFS doesn't support zerofill API",
            tmp);
        ret = -EINVAL;
        goto out;
    }

    sprintf(path, "/%s/%s", gconf->pool, gconf->image);
    fd = yfs_creat(yfs, path,
        O_CREAT | O_TRUNC | O_BINARY | O_RDWR | O_ACCMODE, S_IRUSR | S_IWUSR);
    if (!fd) {
        ret = -errno;
    } else {
        if (!yfs_ftruncate(fd, total_size)) {
            if (prealloc && qemu_yfs_zerofill(fd, 0, total_size)) {
                ret = -errno;
            }
        } else {
            ret = -errno;
        }
        if (yfs_close(fd) != 0) {
            ret = -errno;
        }
    }
out:
    if (tmp) {
        g_free(tmp);
    }
    qemu_yfs_gconf_free(gconf);
    if (yfs) {
        yfs_fini(yfs);
    }
    return ret;
}

static coroutine_fn int qemu_yfs_co_rw(BlockDriverState *bs,
        int64_t sector_num, int nb_sectors, QEMUIOVector *qiov, int write)
{
    int ret;
    YfsAIOCB *acb = g_slice_new(YfsAIOCB);
    BDRVYfsState *s = bs->opaque;
    size_t size = nb_sectors * BDRV_SECTOR_SIZE;
    off_t offset = sector_num * BDRV_SECTOR_SIZE;

    if (s->isroot) {
        ret = -EPERM;
        goto out;
    }

    acb->size = size;
    acb->ret = 0;
    acb->coroutine = qemu_coroutine_self();
    acb->aio_context = bdrv_get_aio_context(bs);

    if (write) {
        ret = yfs_pwritev_async(s->fd, qiov->iov, qiov->niov, offset, 0,
            &yfs_finish_aiocb, acb);
    } else {
        ret = yfs_preadv_async(s->fd, qiov->iov, qiov->niov, offset, 0,
            &yfs_finish_aiocb, acb);
    }

    if (ret < 0) {
        ret = -errno;
        goto out;
    }

    qemu_coroutine_yield();
    ret = acb->ret;

out:
    g_slice_free(YfsAIOCB, acb);
    return ret;
}

static int qemu_yfs_truncate(BlockDriverState *bs, int64_t offset)
{
    int ret;
    BDRVYfsState *s = bs->opaque;
    if (s->isroot) {
        return -EPERM;
    }
    ret = yfs_ftruncate(s->fd, offset);
    if (ret < 0) {
        return -errno;
    }

    return 0;
}

static coroutine_fn int qemu_yfs_co_readv(BlockDriverState *bs,
        int64_t sector_num, int nb_sectors, QEMUIOVector *qiov)
{
    return qemu_yfs_co_rw(bs, sector_num, nb_sectors, qiov, 0);
}

static coroutine_fn int qemu_yfs_co_writev(BlockDriverState *bs,
        int64_t sector_num, int nb_sectors, QEMUIOVector *qiov)
{
    return qemu_yfs_co_rw(bs, sector_num, nb_sectors, qiov, 1);
}

static coroutine_fn int qemu_yfs_co_flush_to_disk(BlockDriverState *bs)
{
    int ret;
    YfsAIOCB *acb = g_slice_new(YfsAIOCB);
    BDRVYfsState *s = bs->opaque;

    if (s->isroot) {
        ret = -EPERM;
        goto out;
    }
    acb->size = 0;
    acb->ret = 0;
    acb->coroutine = qemu_coroutine_self();
    acb->aio_context = bdrv_get_aio_context(bs);

    ret = yfs_fsync_async(s->fd, &yfs_finish_aiocb, acb);
    if (ret < 0) {
        ret = -errno;
        goto out;
    }

    qemu_coroutine_yield();
    ret = acb->ret;

out:
    g_slice_free(YfsAIOCB, acb);
    return ret;
}

#ifdef CONFIG_YFS_DISCARD
static coroutine_fn int qemu_yfs_co_discard(BlockDriverState *bs,
        int64_t sector_num, int nb_sectors)
{
    int ret;
    YfsAIOCB *acb = g_slice_new(YfsAIOCB);
    BDRVYfsState *s = bs->opaque;
    size_t size = nb_sectors * BDRV_SECTOR_SIZE;
    off_t offset = sector_num * BDRV_SECTOR_SIZE;

    acb->size = 0;
    acb->ret = 0;
    acb->coroutine = qemu_coroutine_self();
    acb->aio_context = bdrv_get_aio_context(bs);

    ret = yfs_discard_async(s->fd, offset, size, &yfs_finish_aiocb, acb);
    if (ret < 0) {
        ret = -errno;
        goto out;
    }

    qemu_coroutine_yield();
    ret = acb->ret;

out:
    g_slice_free(YfsAIOCB, acb);
    return ret;
}
#endif

static int64_t qemu_yfs_getlength(BlockDriverState *bs)
{
    BDRVYfsState *s = bs->opaque;
    struct stat st;
    int64_t ret;

    if (s->isroot) {
        return 0;
    }

    ret = yfs_fstat(s->fd, &st);
    if (ret < 0) {
        return -errno;
    } else {
        return st.st_size;
    }
}

static int64_t qemu_yfs_allocated_file_size(BlockDriverState *bs)
{
    BDRVYfsState *s = bs->opaque;
    struct stat st;
    int ret;

    if (s->isroot) {
        return -EPERM;
    }
    ret = yfs_fstat(s->fd, &st);
    if (ret < 0) {
        return -errno;
    } else {
        return st.st_blocks * 512;
    }
}

static void qemu_yfs_close(BlockDriverState *bs)
{
    BDRVYfsState *s = bs->opaque;

    if (s->fd) {
        yfs_close(s->fd);
        s->fd = NULL;
    }
    yfs_fini(s->yfs);
}

static int qemu_yfs_has_zero_init(BlockDriverState *bs)
{
    /* YfsFS volume could be backed by a block device */
    return 0;
}

static QemuOptsList qemu_yfs_create_opts = {
    .name = "qemu-yfs-create-opts",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_yfs_create_opts.head),
    .desc = {
        {
            .name = BLOCK_OPT_SIZE,
            .type = QEMU_OPT_SIZE,
            .help = "Virtual disk size"
        },
        {
            .name = BLOCK_OPT_PREALLOC,
            .type = QEMU_OPT_STRING,
            .help = "Preallocation mode (allowed values: off, full)"
        },

        {
            .name = YBD_OPT_CMD,
            .type = QEMU_OPT_STRING,
            .help = "manager cmd (allowed valued: clone delete)"

        },

        {
            .name = YBD_OPT_IMG,
            .type = QEMU_OPT_STRING,
            .help = "to delete which img"
        },

        {
            .name =  YBD_OPT_TRG,
            .type = QEMU_OPT_STRING,
            .help = "clone to target file"
        },

        {
            .name = YBD_OPT_SNP,
            .type = QEMU_OPT_STRING,
            .help = "clone img snap "

        },
        { /* end of list */ }
    }
};


static int qemu_yfs_snap_create(BlockDriverState *bs,
                                        QEMUSnapshotInfo *sn_info)
{
    BDRVYfsState *s = bs->opaque;
    int r;

    if (s->isroot) {
        return -EPERM;
    }
    if (sn_info->name[0] == '\0') {
        return -EINVAL; /* we need a name for rbd snapshots */
    }

    if (sn_info->id_str[0] != '\0' &&
            strcmp(sn_info->id_str, sn_info->name) != 0) {
        return -EINVAL;
    }


    r = yfs_snap_create(s->fd, sn_info->name);
    if (r < 0) {
        error_report("failed to create snap: %s", strerror(-r));
        return r;
    }

    return 0;
}

static int qemu_yfs_snap_remove(BlockDriverState *bs,const char *snapshot_id,
        const char *snapshot_name,Error **errp)
{
    BDRVYfsState *s = bs->opaque;
    int r;

    if(s->isroot) {
        return -EPERM;
    }
    if (!snapshot_name) {
        error_setg(errp, "yfs need a valid snapshot name");
        return -EINVAL;
    }

    /* If snapshot_id is specified, it must be equal to name, see
     *        qemu_rbd_snap_list() */
    if (snapshot_id && strcmp(snapshot_id, snapshot_name)) {
        error_setg(errp,
                "ybd do not support snapshot id, it should be NULL or "
                "equal to snapshot name");
        return -EINVAL;
    }

    r = yfs_snap_remove(s->fd, snapshot_name);
    if (r < 0) {
        error_setg_errno(errp, -r, "Failed to remove the snapshot");
    }
    return r;
}

static int qemu_yfs_snap_rollback(BlockDriverState *bs, const char *snapshot_name)
{
    BDRVYfsState *s = bs->opaque;
    int r;
    if (s->isroot) {
        return -EPERM;
    }

    r = yfs_snap_rollback(s->fd, snapshot_name);
    return r;
}


static int qemu_yfs_snap_list(BlockDriverState *bs, 
        QEMUSnapshotInfo **psn_tab)
{
    BDRVYfsState *s = bs->opaque;
    QEMUSnapshotInfo *sn_info, *sn_tab = NULL;
    int i, snap_count;
    struct yfs_snap_info_t *snaps;
    int max_snaps = YBD_MAX_SNAPS;

    if (s->isroot) {
        return -EPERM;
    }
    do {
        snaps = g_new(struct yfs_snap_info_t, max_snaps);
        snap_count = yfs_snap_list(s->fd, snaps, &max_snaps);
        if (snap_count <= 0) {
            g_free(snaps);
        }
    } while (snap_count == -ERANGE);

    if (snap_count <= 0) {
        goto done;
    }

    sn_tab = g_new0(QEMUSnapshotInfo, snap_count);

    for (i = 0; i < snap_count; i++) {
        const char *snap_name = snaps[i].name;

        sn_info = sn_tab + i;
        pstrcpy(sn_info->id_str, sizeof(sn_info->id_str), snap_name);
        pstrcpy(sn_info->name, sizeof(sn_info->name), snap_name);

        sn_info->vm_state_size = snaps[i].vm_state_size;
        sn_info->date_sec = (uint32_t)snaps[i].vm_clock_nsec;
        sn_info->date_nsec = 0;
        sn_info->vm_clock_nsec = 0;
    }
    g_free(snaps);

done:
    *psn_tab = sn_tab;
    return snap_count;
}

static int qemu_yfs_amend_options(BlockDriverState *bs, QemuOpts *opts,
        BlockDriverAmendStatusCB *status_cb)
{
    BDRVYfsState *s = bs->opaque;
    if (!s->isroot) {
        printf("only yfs:/root/root can do this opertion");
        return -EPERM;
    }
    QemuOptDesc *desc = opts->list->desc;

    while (desc && desc->name) {
        if (!qemu_opt_find(opts, desc->name)) {
            /* only change explicitly defined options */
            desc++;
            continue;
        }

        if (!strcmp(desc->name, YBD_OPT_CMD)) {
            const char* cmd = qemu_opt_get(opts, YBD_OPT_CMD);
            if (!cmd) {
                /* preserve default */
            } if (!strcmp(cmd, YBD_CMD_DEL)) {
                const char *img = qemu_opt_get(opts, YBD_OPT_IMG);
                if (!img) {
                    printf("del img filename is need\n");
                    return -EINVAL; 
                } else {
                    return yfs_remove(s->yfs, img);
                }
            } else if (!strcmp(cmd, YBD_CMD_CLONE)){
                const char *img = qemu_opt_get(opts, YBD_OPT_IMG);
                const char *snp = qemu_opt_get(opts, YBD_OPT_SNP);
                const char *trg = qemu_opt_get(opts, YBD_OPT_TRG);
                if (!img || !trg) {
                    printf("clone img filename and target filename is need\n");
                    return -EINVAL;
                }

                return yfs_clone(s->yfs, img, snp, trg);

            } else {
                return -EINVAL;
            }
        } 


        desc++;
    }

   
    return -ENOTSUP;
}

static BlockDriver bdrv_yfs = {
    .format_name                  = "yfs",
    .protocol_name                = "yfs",
    .instance_size                = sizeof(BDRVYfsState),
    .bdrv_needs_filename          = true,
    .bdrv_file_open               = qemu_yfs_open,
    .bdrv_reopen_prepare          = qemu_yfs_reopen_prepare,
    .bdrv_reopen_commit           = qemu_yfs_reopen_commit,
    .bdrv_reopen_abort            = qemu_yfs_reopen_abort,
    .bdrv_close                   = qemu_yfs_close,
    .bdrv_create                  = qemu_yfs_create,
    .bdrv_getlength               = qemu_yfs_getlength,
    .bdrv_get_allocated_file_size = qemu_yfs_allocated_file_size,
    .bdrv_truncate                = qemu_yfs_truncate,
    .bdrv_co_readv                = qemu_yfs_co_readv,
    .bdrv_co_writev               = qemu_yfs_co_writev,
    .bdrv_co_flush_to_disk        = qemu_yfs_co_flush_to_disk,
    .bdrv_has_zero_init           = qemu_yfs_has_zero_init,
#ifdef CONFIG_YFS_DISCARD
    .bdrv_co_discard              = qemu_yfs_co_discard,
#endif
#ifdef CONFIG_YFS_ZEROFILL
    .bdrv_co_write_zeroes         = qemu_yfs_co_write_zeroes,
#endif
    .create_opts                  = &qemu_yfs_create_opts,
    .bdrv_snapshot_create   = qemu_yfs_snap_create,
    .bdrv_snapshot_delete   = qemu_yfs_snap_remove,
    .bdrv_snapshot_list     = qemu_yfs_snap_list,
    .bdrv_snapshot_goto     = qemu_yfs_snap_rollback,
    .bdrv_amend_options     = qemu_yfs_amend_options,
};

static BlockDriver bdrv_yfs_tcp = {
    .format_name                  = "yfs",
    .protocol_name                = "yfs+tcp",
    .instance_size                = sizeof(BDRVYfsState),
    .bdrv_needs_filename          = true,
    .bdrv_file_open               = qemu_yfs_open,
    .bdrv_reopen_prepare          = qemu_yfs_reopen_prepare,
    .bdrv_reopen_commit           = qemu_yfs_reopen_commit,
    .bdrv_reopen_abort            = qemu_yfs_reopen_abort,
    .bdrv_close                   = qemu_yfs_close,
    .bdrv_create                  = qemu_yfs_create,
    .bdrv_getlength               = qemu_yfs_getlength,
    .bdrv_get_allocated_file_size = qemu_yfs_allocated_file_size,
    .bdrv_truncate                = qemu_yfs_truncate,
    .bdrv_co_readv                = qemu_yfs_co_readv,
    .bdrv_co_writev               = qemu_yfs_co_writev,
    .bdrv_co_flush_to_disk        = qemu_yfs_co_flush_to_disk,
    .bdrv_has_zero_init           = qemu_yfs_has_zero_init,
#ifdef CONFIG_YFS_DISCARD
    .bdrv_co_discard              = qemu_yfs_co_discard,
#endif
#ifdef CONFIG_YFS_ZEROFILL
    .bdrv_co_write_zeroes         = qemu_yfs_co_write_zeroes,
#endif
    .create_opts                  = &qemu_yfs_create_opts,
};

static BlockDriver bdrv_yfs_unix = {
    .format_name                  = "yfs",
    .protocol_name                = "yfs+unix",
    .instance_size                = sizeof(BDRVYfsState),
    .bdrv_needs_filename          = true,
    .bdrv_file_open               = qemu_yfs_open,
    .bdrv_reopen_prepare          = qemu_yfs_reopen_prepare,
    .bdrv_reopen_commit           = qemu_yfs_reopen_commit,
    .bdrv_reopen_abort            = qemu_yfs_reopen_abort,
    .bdrv_close                   = qemu_yfs_close,
    .bdrv_create                  = qemu_yfs_create,
    .bdrv_getlength               = qemu_yfs_getlength,
    .bdrv_get_allocated_file_size = qemu_yfs_allocated_file_size,
    .bdrv_truncate                = qemu_yfs_truncate,
    .bdrv_co_readv                = qemu_yfs_co_readv,
    .bdrv_co_writev               = qemu_yfs_co_writev,
    .bdrv_co_flush_to_disk        = qemu_yfs_co_flush_to_disk,
    .bdrv_has_zero_init           = qemu_yfs_has_zero_init,
#ifdef CONFIG_YFS_DISCARD
    .bdrv_co_discard              = qemu_yfs_co_discard,
#endif
#ifdef CONFIG_YFS_ZEROFILL
    .bdrv_co_write_zeroes         = qemu_yfs_co_write_zeroes,
#endif
    .create_opts                  = &qemu_yfs_create_opts,
};

static BlockDriver bdrv_yfs_rdma = {
    .format_name                  = "yfs",
    .protocol_name                = "yfs+rdma",
    .instance_size                = sizeof(BDRVYfsState),
    .bdrv_needs_filename          = true,
    .bdrv_file_open               = qemu_yfs_open,
    .bdrv_reopen_prepare          = qemu_yfs_reopen_prepare,
    .bdrv_reopen_commit           = qemu_yfs_reopen_commit,
    .bdrv_reopen_abort            = qemu_yfs_reopen_abort,
    .bdrv_close                   = qemu_yfs_close,
    .bdrv_create                  = qemu_yfs_create,
    .bdrv_getlength               = qemu_yfs_getlength,
    .bdrv_get_allocated_file_size = qemu_yfs_allocated_file_size,
    .bdrv_truncate                = qemu_yfs_truncate,
    .bdrv_co_readv                = qemu_yfs_co_readv,
    .bdrv_co_writev               = qemu_yfs_co_writev,
    .bdrv_co_flush_to_disk        = qemu_yfs_co_flush_to_disk,
    .bdrv_has_zero_init           = qemu_yfs_has_zero_init,
#ifdef CONFIG_YFS_DISCARD
    .bdrv_co_discard              = qemu_yfs_co_discard,
#endif
#ifdef CONFIG_YFS_ZEROFILL
    .bdrv_co_write_zeroes         = qemu_yfs_co_write_zeroes,
#endif
    .create_opts                  = &qemu_yfs_create_opts,
};

static void bdrv_yfs_init(void)
{
    bdrv_register(&bdrv_yfs_rdma);
    bdrv_register(&bdrv_yfs_unix);
    bdrv_register(&bdrv_yfs_tcp);
    bdrv_register(&bdrv_yfs);
}

block_init(bdrv_yfs_init);
