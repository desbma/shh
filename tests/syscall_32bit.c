/* Make a syscall of a given kind on a path, both given as arguments, through the 32-bit x86 ABI */

#define _GNU_SOURCE
#include <err.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Open a path read-only, exiting on failure */
static int open_rdonly(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        err(1, "%s", path);
    }
    return fd;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        errx(2, "Usage: %s KIND PATH", argv[0]);
    }
    const char *kind = argv[1];
    const char *path = argv[2];
    /* Large enough for every stat and statfs structure */
    static char buf[256];
    long ret;
    if (strcmp(kind, "chown32") == 0) {
        ret = syscall(SYS_chown32, path, -1, -1);
    } else if (strcmp(kind, "fchown32") == 0) {
        ret = syscall(SYS_fchown32, open_rdonly(path), -1, -1);
    } else if (strcmp(kind, "fstatat64") == 0) {
        ret = syscall(SYS_fstatat64, AT_FDCWD, path, buf, 0);
    } else if (strcmp(kind, "ioctl-setflags32") == 0) {
        /* Zeroed flags, those of a new tmpfs file */
        int flags = 0;
        ret = ioctl(open_rdonly(path), FS_IOC32_SETFLAGS, &flags);
    } else if (strcmp(kind, "lchown32") == 0) {
        ret = syscall(SYS_lchown32, path, -1, -1);
    } else if (strcmp(kind, "lstat64") == 0) {
        ret = syscall(SYS_lstat64, path, buf);
    } else if (strcmp(kind, "oldlstat") == 0) {
        ret = syscall(SYS_oldlstat, path, buf);
    } else if (strcmp(kind, "oldstat") == 0) {
        ret = syscall(SYS_oldstat, path, buf);
    } else if (strcmp(kind, "stat64") == 0) {
        ret = syscall(SYS_stat64, path, buf);
    } else if (strcmp(kind, "statfs64") == 0) {
        ret = syscall(SYS_statfs64, path, sizeof(struct statfs64), buf);
    } else if (strcmp(kind, "truncate64") == 0) {
        ret = syscall(SYS_truncate64, path, 0, 0);
    } else if (strcmp(kind, "utimensat_time64") == 0) {
        ret = syscall(SYS_utimensat_time64, AT_FDCWD, path, NULL, 0);
    } else {
        errx(2, "Unknown kind: %s", kind);
    }
    if (ret == -1) {
        err(1, "%s", path);
    }
    return 0;
}
