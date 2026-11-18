// KNSH-077 C3: time copy-on-write shadows of a tree (FR-CKP-01, NFR-PERF-06).
//
// usage:
//   clonetree file <src> <dst> [threads=1] [bg|utility]   per-file clonefileat(2), directories recreated (mkdirat)
//   clonetree dir  <src> <dst> [bg|utility]               one clonefile(2) of the root directory (whole subtree)
//   clonetree rm   <dst>                          removefile(3) of a shadow, timed
//   clonetree verify <src> <dst>                  compare every entry's attributes, and content of every 50th file
//   clonetree attrs <scratch>                     which attributes clonefile keeps on one hand-made file
//
// "bg" puts the process in the Darwin background band (PRIO_DARWIN_BG: low CPU priority, throttled disk I/O),
// which is what a background shadow build in knshd would get from QoS "background". "utility" runs every thread at
// QoS utility (pthread_set_qos_class_self_np), the next class up.
//
// Every timed mode prints one tab-separated line:
//   mode threads bg wall_s user_s sys_s files dirs free_before free_after extra_bytes
// free_* come from statfs(2) f_bavail*f_bsize after sync(2) (the syncs are not timed); extra_bytes is their
// difference, so other activity on the volume shows up in it (repeat runs to see the noise).

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <pthread/qos.h>
#include <removefile.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/clonefile.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static long long free_bytes(const char *path) {
    struct statfs s;
    sync();
    if (statfs(path, &s) != 0) return -1;
    return (long long)s.f_bavail * (long long)s.f_bsize;
}

static void die(const char *what, const char *path) {
    fprintf(stderr, "clonetree: %s %s: %s\n", what, path, strerror(errno));
    exit(1);
}

static atomic_long n_files, n_dirs;

// ---- work queue of directories (src path, dst path) -------------------------------------------------------

struct job {
    char *src, *dst;
    struct job *next;
};

static struct job *queue;
static long pending; // jobs queued or running; the walk is done when it reaches 0
static int nthreads;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;

static void push(const char *src, const char *dst) {
    struct job *j = malloc(sizeof *j);
    j->src = strdup(src);
    j->dst = strdup(dst);
    pthread_mutex_lock(&mu);
    j->next = queue;
    queue = j;
    pending++;
    pthread_cond_signal(&cv);
    pthread_mutex_unlock(&mu);
}

// Clone one directory's entries; subdirectories are created here and queued.
static void clone_dir(const char *src, const char *dst) {
    int sfd = open(src, O_RDONLY | O_DIRECTORY);
    if (sfd < 0) die("open", src);
    int dfd = open(dst, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) die("open", dst);
    DIR *d = fdopendir(dup(sfd));
    struct dirent *e;
    char s2[2048], d2[2048];
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        if (e->d_type == DT_DIR) {
            if (mkdirat(dfd, e->d_name, 0700) != 0) die("mkdirat", e->d_name);
            atomic_fetch_add(&n_dirs, 1);
            snprintf(s2, sizeof s2, "%s/%s", src, e->d_name);
            snprintf(d2, sizeof d2, "%s/%s", dst, e->d_name);
            push(s2, d2);
        } else {
            // Regular files and symlinks alike; CLONE_NOFOLLOW clones a symlink itself.
            if (clonefileat(sfd, e->d_name, dfd, e->d_name, CLONE_NOFOLLOW) != 0) die("clonefileat", e->d_name);
            atomic_fetch_add(&n_files, 1);
        }
    }
    closedir(d);
    close(sfd);
    close(dfd);
}

static int use_utility; // run every thread at QoS utility

static void set_utility(void) {
    if (use_utility && pthread_set_qos_class_self_np(QOS_CLASS_UTILITY, 0) != 0) die("qos", "utility");
}

static void *worker(void *arg) {
    (void)arg;
    set_utility();
    for (;;) {
        pthread_mutex_lock(&mu);
        while (queue == NULL && pending > 0) pthread_cond_wait(&cv, &mu);
        if (queue == NULL) { // pending == 0: nothing queued and nothing running
            pthread_mutex_unlock(&mu);
            return NULL;
        }
        struct job *j = queue;
        queue = j->next;
        pthread_mutex_unlock(&mu);
        clone_dir(j->src, j->dst);
        free(j->src);
        free(j->dst);
        free(j);
        pthread_mutex_lock(&mu);
        if (--pending == 0) pthread_cond_broadcast(&cv);
        pthread_mutex_unlock(&mu);
    }
}

static void report(const char *mode, int threads, int bg, double t0, double t1, struct rusage *r0,
                   struct rusage *r1, long long f0, long long f1) {
    double user = (double)(r1->ru_utime.tv_sec - r0->ru_utime.tv_sec) +
                  (double)(r1->ru_utime.tv_usec - r0->ru_utime.tv_usec) / 1e6;
    double sys = (double)(r1->ru_stime.tv_sec - r0->ru_stime.tv_sec) +
                 (double)(r1->ru_stime.tv_usec - r0->ru_stime.tv_usec) / 1e6;
    printf("%s\t%d\t%s\t%.3f\t%.3f\t%.3f\t%ld\t%ld\t%lld\t%lld\t%lld\n", mode, threads,
           bg ? "bg" : use_utility ? "utility" : "normal",
           t1 - t0, user, sys, atomic_load(&n_files), atomic_load(&n_dirs), f0, f1, f0 - f1);
}

static void set_bg(void) {
    if (setpriority(PRIO_DARWIN_PROCESS, 0, PRIO_DARWIN_BG) != 0) die("setpriority", "PRIO_DARWIN_BG");
}

// ---- verify --------------------------------------------------------------------------------------------

static long mism_size, mism_mtime, mism_mode, mism_flags, mism_uid, same_ino, mism_content, mism_xattr, checked,
    content_checked, mism_birth;

static int same_content(const char *a, const char *b) {
    FILE *fa = fopen(a, "rb"), *fb = fopen(b, "rb");
    if (!fa || !fb) return 0;
    static char ba[1 << 16], bb[1 << 16];
    int same = 1;
    for (;;) {
        size_t na = fread(ba, 1, sizeof ba, fa), nb = fread(bb, 1, sizeof bb, fb);
        if (na != nb || memcmp(ba, bb, na) != 0) {
            same = 0;
            break;
        }
        if (na == 0) break;
    }
    fclose(fa);
    fclose(fb);
    return same;
}

static void verify(const char *src, const char *dst) {
    DIR *d = opendir(src);
    if (!d) die("opendir", src);
    struct dirent *e;
    char s2[2048], d2[2048];
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        snprintf(s2, sizeof s2, "%s/%s", src, e->d_name);
        snprintf(d2, sizeof d2, "%s/%s", dst, e->d_name);
        if (e->d_type == DT_DIR) {
            verify(s2, d2);
            continue;
        }
        struct stat a, b;
        if (lstat(s2, &a) != 0) die("lstat", s2);
        if (lstat(d2, &b) != 0) die("lstat", d2);
        checked++;
        if (a.st_size != b.st_size) mism_size++;
        if (a.st_mtimespec.tv_sec != b.st_mtimespec.tv_sec || a.st_mtimespec.tv_nsec != b.st_mtimespec.tv_nsec)
            mism_mtime++;
        if (a.st_birthtimespec.tv_sec != b.st_birthtimespec.tv_sec ||
            a.st_birthtimespec.tv_nsec != b.st_birthtimespec.tv_nsec)
            mism_birth++;
        if (a.st_mode != b.st_mode) mism_mode++;
        if (a.st_flags != b.st_flags) mism_flags++;
        if (a.st_uid != b.st_uid || a.st_gid != b.st_gid) mism_uid++;
        if (a.st_ino == b.st_ino) same_ino++;
        if (listxattr(s2, NULL, 0, XATTR_NOFOLLOW) != listxattr(d2, NULL, 0, XATTR_NOFOLLOW)) mism_xattr++;
        if (checked % 50 == 0) {
            content_checked++;
            if (!same_content(s2, d2)) mism_content++;
        }
    }
    closedir(d);
}

// ---- attrs ---------------------------------------------------------------------------------------------

static void show(const char *label, const char *path) {
    struct stat s;
    if (lstat(path, &s) != 0) die("lstat", path);
    char names[1024];
    ssize_t n = listxattr(path, names, sizeof names, XATTR_NOFOLLOW);
    printf("%s\tino=%llu\tsize=%lld\tmode=%o\tflags=0x%x\tnlink=%d\tmtime=%ld.%09ld\tbirth=%ld.%09ld\t"
           "ctime=%ld.%09ld\txattrs=",
           label, (unsigned long long)s.st_ino, (long long)s.st_size, s.st_mode & 07777, s.st_flags, s.st_nlink,
           s.st_mtimespec.tv_sec, s.st_mtimespec.tv_nsec, s.st_birthtimespec.tv_sec, s.st_birthtimespec.tv_nsec,
           s.st_ctimespec.tv_sec, s.st_ctimespec.tv_nsec);
    for (ssize_t i = 0; i < n; i += (ssize_t)strlen(names + i) + 1) printf("%s%s", i ? "," : "", names + i);
    printf("\n");
}

static void attrs(const char *dir) {
    char src[1024], dst[1024], hard[1024];
    snprintf(src, sizeof src, "%s/attr-src", dir);
    snprintf(dst, sizeof dst, "%s/attr-clone", dir);
    snprintf(hard, sizeof hard, "%s/attr-hardlink", dir);
    unlink(src);
    unlink(dst);
    unlink(hard);
    int fd = open(src, O_WRONLY | O_CREAT, 0644);
    if (fd < 0) die("open", src);
    if (write(fd, "hello\n", 6) != 6) die("write", src);
    close(fd);
    const char *v = "x";
    if (setxattr(src, "org.knsh.spike", v, 1, 0, 0) != 0) die("setxattr", src);
    if (chmod(src, 06755) != 0) die("chmod", src); // setuid and setgid
    if (chflags(src, UF_HIDDEN) != 0) die("chflags", src);
    if (link(src, hard) != 0) die("link", src);
    struct timespec ts[2] = {{1700000000, 123456789}, {1700000000, 123456789}};
    if (utimensat(AT_FDCWD, src, ts, 0) != 0) die("utimensat", src);
    show("source", src);
    if (clonefile(src, dst, 0) != 0) die("clonefile", src);
    show("clone", dst);
    show("source_after", src);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: see header\n");
        return 2;
    }
    const char *mode = argv[1];
    struct rusage r0, r1;
    if (strcmp(mode, "file") == 0 && argc >= 4) {
        nthreads = argc > 4 ? atoi(argv[4]) : 1;
        int bg = argc > 5 && strcmp(argv[5], "bg") == 0;
        use_utility = argc > 5 && strcmp(argv[5], "utility") == 0;
        if (bg) set_bg();
        set_utility();
        long long f0 = free_bytes(argv[2]);
        getrusage(RUSAGE_SELF, &r0);
        double t0 = now();
        if (mkdir(argv[3], 0700) != 0) die("mkdir", argv[3]);
        push(argv[2], argv[3]);
        pthread_t *t = calloc((size_t)nthreads, sizeof *t);
        for (int i = 0; i < nthreads; i++) pthread_create(&t[i], NULL, worker, NULL);
        for (int i = 0; i < nthreads; i++) pthread_join(t[i], NULL);
        double t1 = now();
        getrusage(RUSAGE_SELF, &r1);
        report("file", nthreads, bg, t0, t1, &r0, &r1, f0, free_bytes(argv[2]));
    } else if (strcmp(mode, "dir") == 0 && argc >= 4) {
        int bg = argc > 4 && strcmp(argv[4], "bg") == 0;
        use_utility = argc > 4 && strcmp(argv[4], "utility") == 0;
        if (bg) set_bg();
        set_utility();
        long long f0 = free_bytes(argv[2]);
        getrusage(RUSAGE_SELF, &r0);
        double t0 = now();
        if (clonefile(argv[2], argv[3], 0) != 0) die("clonefile", argv[2]);
        double t1 = now();
        getrusage(RUSAGE_SELF, &r1);
        report("dir", 1, bg, t0, t1, &r0, &r1, f0, free_bytes(argv[2]));
    } else if (strcmp(mode, "rm") == 0) {
        long long f0 = free_bytes(argv[2]);
        getrusage(RUSAGE_SELF, &r0);
        double t0 = now();
        if (removefile(argv[2], NULL, REMOVEFILE_RECURSIVE) != 0) die("removefile", argv[2]);
        double t1 = now();
        getrusage(RUSAGE_SELF, &r1);
        // extra_bytes is negative here: space given back.
        char parent[2048];
        snprintf(parent, sizeof parent, "%s", argv[2]);
        char *slash = strrchr(parent, '/');
        if (slash != NULL && slash != parent) *slash = '\0';
        report("rm", 1, 0, t0, t1, &r0, &r1, f0, free_bytes(parent));
    } else if (strcmp(mode, "verify") == 0 && argc >= 4) {
        verify(argv[2], argv[3]);
        printf("checked\t%ld\nsame_inode\t%ld\nsize_differs\t%ld\nmtime_differs\t%ld\nbirthtime_differs\t%ld\n"
               "mode_differs\t%ld\nflags_differ\t%ld\nowner_differs\t%ld\nxattr_list_differs\t%ld\n"
               "content_checked\t%ld\ncontent_differs\t%ld\n",
               checked, same_ino, mism_size, mism_mtime, mism_birth, mism_mode, mism_flags, mism_uid, mism_xattr,
               content_checked, mism_content);
    } else if (strcmp(mode, "attrs") == 0) {
        attrs(argv[2]);
    } else {
        fprintf(stderr, "usage: see header\n");
        return 2;
    }
    return 0;
}
