"""Make a syscall of a given kind on a path, both given as arguments."""

import ctypes
import errno
import os
import select
import struct
import sys

EVENT_TIMEOUT_S = 5
# Values from <fcntl.h>, <linux/fs.h>, <linux/stat.h>, <sys/fanotify.h> and
# <sys/inotify.h>
AT_FDCWD = -100
AT_HANDLE_FID = 0x200
FAN_CLASS_NOTIF = 0
FAN_MARK_ADD = 1
FAN_MARK_MOUNT = 0x10
FAN_MODIFY = 2
FAN_REPORT_FID = 0x200
FILE_ATTR_SIZE_VER0 = 24
IN_MODIFY = 2
MAX_HANDLE_SZ = 128
STATX_BASIC_STATS = 0x7FF
# x86_64 syscall numbers
SYS_access = 21
SYS_faccessat = 269
SYS_faccessat2 = 439
SYS_fanotify_init = 300
SYS_fanotify_mark = 301
SYS_file_getattr = 468
SYS_file_setattr = 469
SYS_getxattr = 191
SYS_getxattrat = 464
SYS_inotify_add_watch = 254
SYS_inotify_init1 = 294
SYS_lgetxattr = 192
SYS_listxattr = 194
SYS_listxattrat = 465
SYS_llistxattr = 195
SYS_name_to_handle_at = 303
SYS_openat2 = 437
SYS_readlink = 89
SYS_readlinkat = 267
SYS_removexattrat = 466
SYS_setxattrat = 463
SYS_statfs = 137
SYS_statx = 332

kind, path = sys.argv[1:]
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
p = path.encode()
buf = ctypes.create_string_buffer(4096)
size = ctypes.c_size_t(len(buf))


def check(ret: int, allowed_errno: int | None = None) -> int:
    """Return a syscall result, raising its error unless the errno is allowed."""
    err = ctypes.get_errno()
    if ret < 0 and err != allowed_errno:
        raise OSError(err, os.strerror(err), path)
    return ret


match kind:
    case "access":
        check(libc.syscall(SYS_access, p, os.W_OK))
    case "faccessat":
        check(libc.syscall(SYS_faccessat, AT_FDCWD, p, os.W_OK))
    case "faccessat2":
        check(libc.syscall(SYS_faccessat2, AT_FDCWD, p, os.W_OK, 0))
    case "fanotify_mark":
        fd = check(libc.syscall(SYS_fanotify_init, FAN_REPORT_FID, os.O_RDONLY))
        check(
            libc.syscall(
                SYS_fanotify_mark,
                fd,
                FAN_MARK_ADD,
                ctypes.c_uint64(FAN_MODIFY),
                AT_FDCWD,
                p,
            )
        )
    case "fanotify_mark-mount":
        # Wait for a write to the path from another process
        fd = check(libc.syscall(SYS_fanotify_init, FAN_CLASS_NOTIF, os.O_RDONLY))
        check(
            libc.syscall(
                SYS_fanotify_mark,
                fd,
                FAN_MARK_ADD | FAN_MARK_MOUNT,
                ctypes.c_uint64(FAN_MODIFY),
                AT_FDCWD,
                p,
            )
        )
        if not select.select([fd], [], [], EVENT_TIMEOUT_S)[0]:
            raise TimeoutError(f"No event from the mount of {path}")
    case "file_getattr":
        check(
            libc.syscall(
                SYS_file_getattr,
                AT_FDCWD,
                p,
                buf,
                ctypes.c_size_t(FILE_ATTR_SIZE_VER0),
                0,
            )
        )
    case "file_setattr":
        check(
            libc.syscall(
                SYS_file_setattr,
                AT_FDCWD,
                p,
                buf,
                ctypes.c_size_t(FILE_ATTR_SIZE_VER0),
                0,
            )
        )
    case "getxattr":
        check(libc.syscall(SYS_getxattr, p, b"user.absent", buf, size), errno.ENODATA)
    case "getxattrat":
        # struct xattr_args: value pointer, size, flags
        args = struct.pack("QII", ctypes.addressof(buf), len(buf), 0)
        check(
            libc.syscall(
                SYS_getxattrat,
                AT_FDCWD,
                p,
                0,
                b"user.absent",
                args,
                ctypes.c_size_t(len(args)),
            ),
            errno.ENODATA,
        )
    case "inotify_add_watch":
        check(
            libc.syscall(
                SYS_inotify_add_watch,
                check(libc.syscall(SYS_inotify_init1, 0)),
                p,
                IN_MODIFY,
            )
        )
    case "lgetxattr":
        check(libc.syscall(SYS_lgetxattr, p, b"user.absent", buf, size), errno.ENODATA)
    case "listxattr":
        check(libc.syscall(SYS_listxattr, p, buf, size))
    case "listxattrat":
        check(libc.syscall(SYS_listxattrat, AT_FDCWD, p, 0, buf, size))
    case "llistxattr":
        check(libc.syscall(SYS_llistxattr, p, buf, size))
    case "name_to_handle_at":
        # struct file_handle of MAX_HANDLE_SZ bytes
        struct.pack_into("I", buf, 0, MAX_HANDLE_SZ)
        check(
            libc.syscall(
                SYS_name_to_handle_at,
                AT_FDCWD,
                p,
                buf,
                ctypes.byref(ctypes.c_int()),
                AT_HANDLE_FID,
            )
        )
    case "name_to_handle_at-size":
        # struct file_handle of 0 bytes
        struct.pack_into("I", buf, 0, 0)
        check(
            libc.syscall(
                SYS_name_to_handle_at,
                AT_FDCWD,
                p,
                buf,
                ctypes.byref(ctypes.c_int()),
                AT_HANDLE_FID,
            ),
            errno.EOVERFLOW,
        )
    case "openat2":
        # struct open_how: flags, mode, resolve
        how = struct.pack("QQQ", os.O_WRONLY | os.O_CREAT, 0o644, 0)
        check(libc.syscall(SYS_openat2, AT_FDCWD, p, how, ctypes.c_size_t(len(how))))
    case "readlink":
        check(libc.syscall(SYS_readlink, p, buf, len(buf)))
    case "readlink-file":
        check(libc.syscall(SYS_readlink, p, buf, len(buf)), errno.EINVAL)
    case "readlinkat":
        check(libc.syscall(SYS_readlinkat, AT_FDCWD, p, buf, len(buf)))
    case "removexattrat":
        check(
            libc.syscall(SYS_removexattrat, AT_FDCWD, p, 0, b"user.absent"),
            errno.ENODATA,
        )
    case "setxattrat":
        value = ctypes.create_string_buffer(b"value")
        # struct xattr_args: value pointer, size, flags
        args = struct.pack("QII", ctypes.addressof(value), len(value.value), 0)
        check(
            libc.syscall(
                SYS_setxattrat,
                AT_FDCWD,
                p,
                0,
                b"user.test",
                args,
                ctypes.c_size_t(len(args)),
            )
        )
    case "statfs":
        check(libc.syscall(SYS_statfs, p, buf))
    case "statx":
        check(libc.syscall(SYS_statx, AT_FDCWD, p, 0, STATX_BASIC_STATS, buf))
    case _:
        raise ValueError(kind)
