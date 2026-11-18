// KNSH-077 C3: what a copy-on-write clone holds when another process has unflushed memory-mapped writes
// (FR-CKP-24 "possibly torn"), and whether such a writer can be seen from outside.
//
// usage: mmapclone <scratch dir> [settle seconds=40]
//
// Every case uses a fresh 16 MiB file of 'A' bytes, written with write(2) and fsync(2). A forked writer process
// (a separate process, as an agent's tool would be) maps it MAP_SHARED and stores bytes without msync(2); the
// parent then reads, stats and clones the file and counts which bytes each view holds.
//
//   dirty    writer stores 'B' into the first 8 MiB, no msync, keeps the mapping: stat, read(2), clone;
//            then writer msync(MS_SYNC): stat, clone; then writer stores 'C' in the last 8 MiB, closes its
//            descriptor, munmaps without msync and exits: stat, clone, then stat every 5 s for <settle> s
//            (does mtime ever move once the dirty pages are written back by the system?)
//   extend   writer ftruncate(2)s the file to 32 MiB and stores 'D' past the old end, no msync: stat, clone
//   torn     writer rewrites every 16 KiB page in a loop, each pass stamping a new generation number into
//            every page, no msync; the parent clones 200 times while it runs and counts clones whose pages
//            carry more than one generation. Repeated with a pwrite(2) writer for comparison
//   observe  whether the writer can be found while it (a) has the file open for writing and mapped,
//            (b) has closed the descriptor but keeps the mapping, (c) has exited: proc_listpidspath(3) over
//            all processes, then per process the open descriptors (PROC_PIDFDVNODEPATHINFO, open flags) and
//            mapped regions (PROC_PIDREGIONPATHINFO, protection), with the time each scan takes
//
// Output: one "key<TAB>value..." line per observation.

#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/clonefile.h>
#include <sys/mman.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MiB (1024 * 1024)
#define SIZE (16 * MiB)
#define PAGE (16 * 1024)

static char dir[1024], path[1200];
static int clone_n;

static void die(const char *what) {
    fprintf(stderr, "mmapclone: %s: %s\n", what, strerror(errno));
    exit(1);
}

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void fresh_file(void) {
    unlink(path);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) die("open");
    static char buf[MiB];
    memset(buf, 'A', sizeof buf);
    for (int i = 0; i < SIZE / MiB; i++)
        if (write(fd, buf, sizeof buf) != (ssize_t)sizeof buf) die("write");
    if (fsync(fd) != 0) die("fsync");
    close(fd);
    sleep(1); // so a later mtime change is visible at one-second granularity too
}

// Count bytes per letter in a file read with read(2).
static void count(const char *label, const char *p) {
    int fd = open(p, O_RDONLY);
    if (fd < 0) die("open for count");
    long n[256] = {0};
    static unsigned char buf[MiB];
    ssize_t r;
    while ((r = read(fd, buf, sizeof buf)) > 0)
        for (ssize_t i = 0; i < r; i++) n[buf[i]]++;
    close(fd);
    printf("%s\tcontent", label);
    for (int c = 0; c < 256; c++)
        if (n[c]) printf("\t%c=%ld", c >= 32 && c < 127 ? c : '?', n[c]);
    printf("\n");
}

static void statline(const char *label, const char *p) {
    struct stat s;
    if (stat(p, &s) != 0) die("stat");
    printf("%s\tstat\tsize=%lld\tmtime=%ld.%09ld\tctime=%ld.%09ld\n", label, (long long)s.st_size,
           s.st_mtimespec.tv_sec, s.st_mtimespec.tv_nsec, s.st_ctimespec.tv_sec, s.st_ctimespec.tv_nsec);
}

static char *clone_now(const char *label) {
    static char cp[1300];
    snprintf(cp, sizeof cp, "%s/clone-%d", dir, clone_n++);
    unlink(cp);
    double t0 = now();
    if (clonefile(path, cp, 0) != 0) die("clonefile");
    printf("%s\tclone_ms\t%.3f\n", label, (now() - t0) * 1e3);
    char sl[256];
    snprintf(sl, sizeof sl, "%s.source", label);
    statline(sl, path);
    statline(label, cp);
    count(label, cp);
    return cp;
}

// ---- writer process: commands arrive one byte at a time on a pipe; each is acknowledged ----

static int to_child[2], to_parent[2];

static void ack(void) {
    if (write(to_parent[1], "k", 1) != 1) _exit(3);
}

static void writer_loop(void) {
    int fd = open(path, O_RDWR);
    if (fd < 0) _exit(2);
    size_t len = SIZE;
    char *m = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) _exit(2);
    ack();
    char c;
    while (read(to_child[0], &c, 1) == 1) {
        switch (c) {
        case 'B': memset(m, 'B', 8 * MiB); break;
        case 'S': msync(m, len, MS_SYNC); break;
        case 'C': memset(m + 8 * MiB, 'C', 8 * MiB); break;
        case 'X': close(fd); fd = -1; break;                  // close the descriptor, keep the mapping
        case 'U': munmap(m, len); ack(); _exit(0);             // unmap without msync and exit
        case 'E':                                             // extend, then store past the old end
            munmap(m, len);
            if (ftruncate(fd, 2 * SIZE) != 0) _exit(2);
            len = 2 * SIZE;
            m = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if (m == MAP_FAILED) _exit(2);
            memset(m + SIZE, 'D', SIZE);
            break;
        default: break;
        }
        ack();
    }
    _exit(0);
}

static pid_t start_writer(void) {
    if (pipe(to_child) != 0 || pipe(to_parent) != 0) die("pipe");
    pid_t pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        close(to_child[1]);
        close(to_parent[0]);
        writer_loop();
    }
    close(to_child[0]);
    close(to_parent[1]);
    char k;
    if (read(to_parent[0], &k, 1) != 1) die("writer start");
    return pid;
}

static void cmd(char c) {
    char k;
    if (write(to_child[1], &c, 1) != 1 || read(to_parent[0], &k, 1) != 1) die("writer command");
}

static void reap(pid_t pid) {
    close(to_child[1]);
    close(to_parent[0]);
    waitpid(pid, NULL, 0);
}

// ---- observe ----

// <mach/vm_region.h> SM_* values.
static const char *share_mode_name(int m) {
    static const char *names[] = {"?", "COW", "PRIVATE", "EMPTY", "SHARED", "TRUESHARED", "PRIVATE_ALIASED",
                                  "SHARED_ALIASED", "LARGE_PAGE"};
    return m >= 0 && m < 9 ? names[m] : "?";
}

static void observe(const char *label) {
    double t0 = now();
    int pids[4096];
    int nbytes = proc_listpidspath(PROC_ALL_PIDS, 0, path, 0, pids, sizeof pids);
    double t1 = now();
    int raw = nbytes > 0 ? nbytes / (int)sizeof(int) : 0, n = 0;
    for (int i = 0; i < raw; i++) {
        int dup = 0;
        for (int j = 0; j < n; j++) dup |= pids[j] == pids[i];
        if (!dup) pids[n++] = pids[i];
    }
    printf("%s\tlistpidspath\tpids=%d\tms=%.2f", label, n, (t1 - t0) * 1e3);
    for (int i = 0; i < n; i++) printf("\t%d", pids[i]);
    printf("\n");
    for (int i = 0; i < n; i++) {
        int pid = pids[i];
        // Open descriptors on the file, with their open flags.
        struct proc_fdinfo fds[1024];
        int fb = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, sizeof fds);
        for (int k = 0; fb > 0 && k < fb / (int)sizeof(struct proc_fdinfo); k++) {
            if (fds[k].proc_fdtype != PROX_FDTYPE_VNODE) continue;
            struct vnode_fdinfowithpath vi;
            if (proc_pidfdinfo(pid, fds[k].proc_fd, PROC_PIDFDVNODEPATHINFO, &vi, sizeof vi) <= 0) continue;
            if (strcmp(vi.pvip.vip_path, path) != 0) continue;
            printf("%s\tfd\tpid=%d\tfd=%d\topenflags=0x%x\twrite=%s\n", label, pid, fds[k].proc_fd,
                   vi.pfi.fi_openflags, (vi.pfi.fi_openflags & FWRITE) ? "yes" : "no");
        }
        // Mapped regions of the file, with their protection.
        uint64_t addr = 0;
        for (int guard = 0; guard < 100000; guard++) {
            struct proc_regionwithpathinfo ri;
            if (proc_pidinfo(pid, PROC_PIDREGIONPATHINFO, addr, &ri, sizeof ri) <= 0) break;
            if (strcmp(ri.prp_vip.vip_path, path) == 0)
                printf("%s\tmap\tpid=%d\taddr=0x%llx\tsize=%llu\tprot=%d\tshare_mode=%s\n", label, pid,
                       (unsigned long long)ri.prp_prinfo.pri_address, (unsigned long long)ri.prp_prinfo.pri_size,
                       ri.prp_prinfo.pri_protection, share_mode_name(ri.prp_prinfo.pri_share_mode));
            addr = ri.prp_prinfo.pri_address + ri.prp_prinfo.pri_size;
        }
    }
}

// ---- torn ----

static volatile sig_atomic_t stop_writer;
static void on_term(int s) {
    (void)s;
    stop_writer = 1;
}

static void torn_writer(int use_pwrite) {
    signal(SIGTERM, on_term);
    int fd = open(path, O_RDWR);
    if (fd < 0) _exit(2);
    char *m = use_pwrite ? NULL : mmap(NULL, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) _exit(2);
    static char page[PAGE];
    ack();
    for (uint64_t gen = 1; !stop_writer; gen++) {
        for (size_t off = 0; off < SIZE && !stop_writer; off += PAGE) {
            if (use_pwrite) {
                memcpy(page, &gen, sizeof gen);
                if (pwrite(fd, page, PAGE, (off_t)off) != PAGE) _exit(2);
            } else {
                memcpy(m + off, &gen, sizeof gen);
            }
        }
    }
    _exit(0);
}

static void torn(const char *label, int use_pwrite) {
    fresh_file();
    if (pipe(to_child) != 0 || pipe(to_parent) != 0) die("pipe");
    pid_t pid = fork();
    if (pid == 0) torn_writer(use_pwrite);
    char k;
    if (read(to_parent[0], &k, 1) != 1) die("torn writer start");
    usleep(100000);
    int torn_clones = 0, total = 200;
    long max_distinct = 0;
    char cp[1300];
    snprintf(cp, sizeof cp, "%s/torn-clone", dir);
    for (int i = 0; i < total; i++) {
        unlink(cp);
        if (clonefile(path, cp, 0) != 0) die("clonefile");
        int fd = open(cp, O_RDONLY);
        // A clone is torn when its pages carry more than one generation: count runs of equal generations.
        uint64_t prev = 0, g;
        long distinct = 0;
        for (off_t off = 0; off < SIZE; off += PAGE) {
            if (pread(fd, &g, sizeof g, off) != sizeof g) die("pread");
            if (off == 0 || g != prev) distinct++;
            prev = g;
        }
        close(fd);
        if (distinct > 1) torn_clones++;
        if (distinct > max_distinct) max_distinct = distinct;
        usleep(5000);
    }
    kill(pid, SIGTERM);
    waitpid(pid, NULL, 0);
    close(to_child[0]);
    close(to_child[1]);
    close(to_parent[0]);
    close(to_parent[1]);
    printf("%s\ttorn\tclones=%d\ttorn_clones=%d\tmax_generation_runs=%ld\n", label, total, torn_clones,
           max_distinct);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: mmapclone <scratch dir> [settle seconds]\n");
        return 2;
    }
    if (realpath(argv[1], dir) == NULL) die("realpath");
    int settle = argc > 2 ? atoi(argv[2]) : 40;
    snprintf(path, sizeof path, "%s/mapped.bin", dir);

    // dirty
    fresh_file();
    statline("dirty.before", path);
    pid_t w = start_writer();
    cmd('B');
    statline("dirty.after_store_B_no_msync", path);
    count("dirty.after_store_B_no_msync.read", path);
    clone_now("dirty.clone_unflushed");
    observe("observe.open_rw_and_mapped");
    cmd('S');
    statline("dirty.after_msync", path);
    clone_now("dirty.clone_after_msync");
    cmd('C');
    cmd('X');
    observe("observe.closed_fd_still_mapped");
    char k;
    if (write(to_child[1], "U", 1) != 1 || read(to_parent[0], &k, 1) != 1) die("writer exit");
    reap(w);
    observe("observe.after_exit");
    statline("dirty.after_store_C_unmap_exit", path);
    clone_now("dirty.clone_after_exit");
    for (int t = 5; t <= settle; t += 5) {
        sleep(5);
        char l[64];
        snprintf(l, sizeof l, "dirty.settle_%ds", t);
        statline(l, path);
    }

    // extend
    fresh_file();
    statline("extend.before", path);
    w = start_writer();
    cmd('E');
    statline("extend.after_ftruncate_and_store", path);
    clone_now("extend.clone_unflushed");
    if (write(to_child[1], "U", 1) != 1 || read(to_parent[0], &k, 1) != 1) die("writer exit");
    reap(w);

    torn("torn.mmap", 0);
    torn("torn.pwrite", 1);
    return 0;
}
