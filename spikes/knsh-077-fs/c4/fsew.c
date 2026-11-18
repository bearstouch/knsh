// KNSH-077 C4: does FSEventStreamFlushSync at the end of a supervised line deliver the writes other processes made
// milliseconds earlier (FR-CKP-03, FR-CKP-05), and how do dropped events surface (FR-CKP-04)?
//
// usage:
//   fsew run <root> <writers> <rounds> <ops> <latency_s> <procedure> [nodefer] [outside]
//       One stream (file events) on <root>. Each round is one "line": <writers> separate processes start
//       together, each makes <ops> creates, ops/6 appends to existing files, ops/4 renames and removes the
//       previous round's files in its own folder, logging the mach time after each call (over a pipe, so the log
//       makes no file events). The line ends when every writer has exited (waitpid). The line-end procedure:
//         flush   FSEventStreamFlushSync
//         none    nothing (control: what has already arrived)
//         marker  create a marker file, then wait (5 s at most) until its event arrives; no flush
//         mflush  create a marker file, then FSEventStreamFlushSync once
//         mloop   create a marker file, then FSEventStreamFlushSync every millisecond until the marker's event
//                 has arrived (5 s at most)
//       The 5 s caps are a clock deadline. The callback itself notes when the current marker's event arrives, so
//       checking for it costs nothing and never holds the lock the callback needs. (An earlier version scanned
//       every recorded event per check, which inflated procedure times; the committed results are from this one.)
//       "outside" puts the markers in <root>-markers, a sibling folder the same stream also watches, as an engine
//       folder on the same volume would be. Then every operation of the round is checked against the events delivered so far. After the last round
//       the stream is flushed again 3 s later, and anything that arrived after its round's line end is "late".
//       An operation is matched by path and flag (create: ItemCreated, append: ItemModified, rename:
//       ItemRenamed on the old and the new path, remove: ItemRemoved).
//   fsew overflow <root> <writers> <ops> <block_s>
//       Blocks the stream's callback queue for <block_s> s while <writers> processes each create, write and remove
//       <ops> files, then records every flag seen and the path of each event carrying a drop or rescan flag.
//   fsew rootchange <root>
//       Stream with WatchRoot on <root>/watched, which is then renamed away and back.
//   fsew mmap <root> [settle_s=40]
//       Which events a writer that changes a file only through a shared mapping produces: no msync then exit;
//       msync then exit; write(2) for comparison; no msync, and msync, while the writer stays alive (descriptor
//       and mapping held) for <settle_s> s, then SIGKILL. Each look first settles the stream (marker + flush loop).
//   fsew writer <dir> <round> <ops>      (internal) one writer of `run`
//   fsew burst <dir> <ops>               (internal) one writer of `overflow`
//
// Paths printed are relative to <root>.

#include <CoreServices/CoreServices.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach/mach_time.h>
#include <poll.h>
#include <signal.h>
#include <pthread.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static mach_timebase_info_data_t tb;
static double ms_of(uint64_t ticks) { return (double)ticks * tb.numer / tb.denom / 1e6; }

static void die(const char *what) {
    fprintf(stderr, "fsew: %s: %s\n", what, strerror(errno));
    exit(1);
}

// ---- events ----------------------------------------------------------------------------------------------

struct ev {
    uint64_t t; // mach time when the callback saw it
    uint32_t flags;
    uint64_t id;
    char *path;
};

static struct ev *evs;
static size_t nevs, capevs;
static pthread_mutex_t evmu = PTHREAD_MUTEX_INITIALIZER;
static volatile int block_once_s;     // overflow: block the queue this long on the first callback
static char rootpath[PATH_MAX];
static size_t rootlen;

// The marker file the line-end procedure is waiting for; the callback sets marker_hit when its event arrives.
static char current_marker[PATH_MAX];
static volatile int marker_hit;

static void callback(ConstFSEventStreamRef s, void *info, size_t n, void *paths, const FSEventStreamEventFlags *fl,
                     const FSEventStreamEventId *ids) {
    (void)s;
    (void)info;
    uint64_t t = mach_absolute_time();
    char **p = paths;
    pthread_mutex_lock(&evmu);
    for (size_t i = 0; i < n; i++) {
        if (nevs == capevs) {
            capevs = capevs ? capevs * 2 : 65536;
            evs = realloc(evs, capevs * sizeof *evs);
        }
        evs[nevs++] = (struct ev){t, fl[i], ids[i], strdup(p[i])};
        if (current_marker[0] && strcmp(p[i], current_marker) == 0) marker_hit = 1;
    }
    pthread_mutex_unlock(&evmu);
    if (block_once_s) {
        int b = block_once_s;
        block_once_s = 0;
        sleep((unsigned)b);
    }
}

static FSEventStreamRef stream;
static dispatch_queue_t q;

// Watches <watch>, and also <also> when it is not NULL (one stream, two paths).
static void start_stream2(const char *watch, const char *also, double latency, FSEventStreamCreateFlags extra) {
    CFStringRef cs[2] = {CFStringCreateWithCString(NULL, watch, kCFStringEncodingUTF8),
                         also ? CFStringCreateWithCString(NULL, also, kCFStringEncodingUTF8) : NULL};
    CFArrayRef arr = CFArrayCreate(NULL, (const void **)cs, also ? 2 : 1, &kCFTypeArrayCallBacks);
    stream = FSEventStreamCreate(NULL, callback, NULL, arr, kFSEventStreamEventIdSinceNow, latency,
                                 kFSEventStreamCreateFlagFileEvents | extra);
    if (!stream) die("FSEventStreamCreate");
    q = dispatch_queue_create("fsew", DISPATCH_QUEUE_SERIAL);
    FSEventStreamSetDispatchQueue(stream, q);
    if (!FSEventStreamStart(stream)) die("FSEventStreamStart");
}

static void start_stream(const char *watch, double latency, FSEventStreamCreateFlags extra) {
    start_stream2(watch, NULL, latency, extra);
}

static void stop_stream(void) {
    FSEventStreamStop(stream);
    FSEventStreamInvalidate(stream);
    FSEventStreamRelease(stream);
}

static size_t snapshot(void) {
    pthread_mutex_lock(&evmu);
    size_t n = nevs;
    pthread_mutex_unlock(&evmu);
    return n;
}

static void clear_events(void) {
    pthread_mutex_lock(&evmu);
    for (size_t i = 0; i < nevs; i++) free(evs[i].path);
    nevs = 0;
    pthread_mutex_unlock(&evmu);
}

static const char *rel(const char *p) { return strncmp(p, rootpath, rootlen) == 0 ? p + rootlen : p; }

static void flagnames(uint32_t f, char *out, size_t n) {
    static const struct {
        uint32_t bit;
        const char *name;
    } F[] = {
        {kFSEventStreamEventFlagMustScanSubDirs, "MustScanSubDirs"},
        {kFSEventStreamEventFlagUserDropped, "UserDropped"},
        {kFSEventStreamEventFlagKernelDropped, "KernelDropped"},
        {kFSEventStreamEventFlagEventIdsWrapped, "EventIdsWrapped"},
        {kFSEventStreamEventFlagHistoryDone, "HistoryDone"},
        {kFSEventStreamEventFlagRootChanged, "RootChanged"},
        {kFSEventStreamEventFlagMount, "Mount"},
        {kFSEventStreamEventFlagUnmount, "Unmount"},
        {kFSEventStreamEventFlagItemCreated, "Created"},
        {kFSEventStreamEventFlagItemRemoved, "Removed"},
        {kFSEventStreamEventFlagItemInodeMetaMod, "InodeMetaMod"},
        {kFSEventStreamEventFlagItemRenamed, "Renamed"},
        {kFSEventStreamEventFlagItemModified, "Modified"},
        {kFSEventStreamEventFlagItemFinderInfoMod, "FinderInfoMod"},
        {kFSEventStreamEventFlagItemChangeOwner, "ChangeOwner"},
        {kFSEventStreamEventFlagItemXattrMod, "XattrMod"},
        {kFSEventStreamEventFlagItemIsFile, "IsFile"},
        {kFSEventStreamEventFlagItemIsDir, "IsDir"},
        {kFSEventStreamEventFlagItemIsSymlink, "IsSymlink"},
        {kFSEventStreamEventFlagOwnEvent, "OwnEvent"},
        {kFSEventStreamEventFlagItemIsHardlink, "IsHardlink"},
        {kFSEventStreamEventFlagItemIsLastHardlink, "IsLastHardlink"},
        {kFSEventStreamEventFlagItemCloned, "Cloned"},
    };
    out[0] = 0;
    for (size_t i = 0; i < sizeof F / sizeof F[0]; i++)
        if (f & F[i].bit) {
            strlcat(out, out[0] ? "|" : "", n);
            strlcat(out, F[i].name, n);
        }
    if (!out[0]) strlcpy(out, "None", n);
}

// ---- spawning this binary as a writer ----------------------------------------------------------------------

static char self[PATH_MAX];

static pid_t spawn_self(char *const args[], int *outfd) {
    int p[2];
    if (pipe(p) != 0) die("pipe");
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, p[1], 1);
    posix_spawn_file_actions_addclose(&fa, p[0]);
    pid_t pid;
    if (posix_spawn(&pid, self, &fa, NULL, args, environ) != 0) die("posix_spawn");
    posix_spawn_file_actions_destroy(&fa);
    close(p[1]);
    *outfd = p[0];
    return pid;
}

// ---- writer (one per process per round) --------------------------------------------------------------------

static char logbuf[1 << 20];
static size_t loglen;

static void logop(char kind, const char *a, const char *b) {
    loglen += (size_t)snprintf(logbuf + loglen, sizeof logbuf - loglen, "%llu %c %s%s%s\n",
                               (unsigned long long)mach_absolute_time(), kind, a, b ? " " : "", b ? b : "");
}

static int writer(const char *dir, int round, int ops) {
    char a[PATH_MAX], b[PATH_MAX];
    static char data[512];
    memset(data, 'x', sizeof data);
    for (int k = 0; k < ops; k++) {
        snprintf(a, sizeof a, "%s/c-%d-%d", dir, round, k);
        int fd = open(a, O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd < 0 || write(fd, data, sizeof data) != (ssize_t)sizeof data) die("writer create");
        close(fd);
        logop('C', a, NULL);
    }
    for (int k = 0; k < ops / 6; k++) {
        snprintf(a, sizeof a, "%s/m-%d-%d", dir, round, k);
        int fd = open(a, O_WRONLY | O_APPEND);
        if (fd < 0 || write(fd, data, 64) != 64) die("writer append");
        close(fd);
        logop('M', a, NULL);
    }
    for (int k = 0; k < ops; k += 4) {
        snprintf(a, sizeof a, "%s/c-%d-%d", dir, round, k);
        snprintf(b, sizeof b, "%s/c-%d-%d.mv", dir, round, k);
        if (rename(a, b) != 0) die("writer rename");
        logop('R', a, b);
    }
    if (round > 0)
        for (int k = 0; k < ops; k++) {
            snprintf(a, sizeof a, "%s/c-%d-%d%s", dir, round - 1, k, k % 4 == 0 ? ".mv" : "");
            if (unlink(a) != 0) die("writer unlink");
            logop('D', a, NULL);
        }
    // The log goes out only after the last operation, so writing it cannot delay any operation.
    for (size_t off = 0; off < loglen;) {
        ssize_t w = write(1, logbuf + off, loglen - off);
        if (w <= 0) die("writer log");
        off += (size_t)w;
    }
    return 0;
}

// ---- run ---------------------------------------------------------------------------------------------------

struct expect {
    uint64_t t;      // mach time the operation completed
    uint32_t bit;    // flag that must appear on an event for path
    char *path;
    int round;
    int last;        // the writer's last operation of the round
    int64_t match;   // index of the first matching event, -1 if none
};

static struct expect *exps;
static size_t nexps, capexps;

static void add_expect(uint64_t t, uint32_t bit, const char *path, int round) {
    if (nexps == capexps) {
        capexps = capexps ? capexps * 2 : 65536;
        exps = realloc(exps, capexps * sizeof *exps);
    }
    exps[nexps++] = (struct expect){t, bit, strdup(path), round, 0, -1};
}

// Parse one writer's log into expectations; the last line is the writer's last operation.
static void parse_log(char *text, int round) {
    size_t first = nexps;
    for (char *line = strtok(text, "\n"); line; line = strtok(NULL, "\n")) {
        unsigned long long t;
        char kind;
        char a[PATH_MAX], b[PATH_MAX];
        b[0] = 0;
        if (sscanf(line, "%llu %c %s %s", &t, &kind, a, b) < 3) continue;
        switch (kind) {
        case 'C': add_expect(t, kFSEventStreamEventFlagItemCreated, a, round); break;
        case 'M': add_expect(t, kFSEventStreamEventFlagItemModified, a, round); break;
        case 'D': add_expect(t, kFSEventStreamEventFlagItemRemoved, a, round); break;
        case 'R':
            add_expect(t, kFSEventStreamEventFlagItemRenamed, a, round);
            add_expect(t, kFSEventStreamEventFlagItemRenamed, b, round);
            break;
        default: break;
        }
    }
    if (nexps > first) {
        uint64_t tl = exps[nexps - 1].t;
        for (size_t i = first; i < nexps; i++) exps[i].last = exps[i].t == tl;
    }
}

static int cmp_dbl(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

static void dist(const char *label, double *v, size_t n) {
    if (n == 0) {
        printf("%s\tn=0\n", label);
        return;
    }
    qsort(v, n, sizeof *v, cmp_dbl);
#define PCT(p) v[(size_t)((p) * (double)(n - 1) + 0.5)]
    printf("%s\tn=%zu\tmin=%.2f\tp50=%.2f\tp95=%.2f\tp99=%.2f\tmax=%.2f\n", label, n, v[0], PCT(0.50), PCT(0.95),
           PCT(0.99), v[n - 1]);
}

// Index events by path (sorted copy) for matching.
static size_t *order;
static int cmp_evpath(const void *a, const void *b) {
    const struct ev *x = &evs[*(const size_t *)a], *y = &evs[*(const size_t *)b];
    int c = strcmp(x->path, y->path);
    if (c) return c;
    return x->t < y->t ? -1 : x->t > y->t;
}

static int64_t find_match(const char *path, uint32_t bit, uint64_t not_before) {
    size_t lo = 0, hi = nevs;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (strcmp(evs[order[mid]].path, path) < 0) lo = mid + 1;
        else hi = mid;
    }
    for (size_t i = lo; i < nevs && strcmp(evs[order[i]].path, path) == 0; i++)
        if ((evs[order[i]].flags & bit) && evs[order[i]].t >= not_before) return (int64_t)order[i];
    return -1;
}

static void flag_histogram(void);

// Arm the wait for <marker> (before the file is created, so its event cannot be missed).
static void arm_marker(const char *marker) {
    pthread_mutex_lock(&evmu);
    strlcpy(current_marker, marker, sizeof current_marker);
    marker_hit = 0;
    pthread_mutex_unlock(&evmu);
}

static int marker_arrived(void) {
    pthread_mutex_lock(&evmu);
    int hit = marker_hit;
    pthread_mutex_unlock(&evmu);
    return hit;
}

// Wait until the armed marker's event arrives or 5 s pass; flush before each look when asked.
static void wait_marker(int flush) {
    uint64_t deadline = mach_absolute_time() + (uint64_t)(5e9 * tb.denom / tb.numer);
    while (!marker_arrived() && mach_absolute_time() < deadline) {
        if (flush) FSEventStreamFlushSync(stream);
        if (marker_arrived()) break;
        usleep(1000);
    }
}

static int run(int writers, int rounds, int ops, double latency, const char *proc, int nodefer, int outside) {
    // Folders and the files each round appends to, made before the stream starts.
    char d[PATH_MAX];
    for (int w = 0; w < writers; w++) {
        snprintf(d, sizeof d, "%s/w%d", rootpath, w);
        if (mkdir(d, 0755) != 0 && errno != EEXIST) die("mkdir");
        for (int r = 0; r < rounds; r++)
            for (int k = 0; k < ops / 6; k++) {
                char f[PATH_MAX];
                snprintf(f, sizeof f, "%s/m-%d-%d", d, r, k);
                int fd = open(f, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (fd < 0) die("precreate");
                close(fd);
            }
    }
    // "outside": markers go to a sibling folder (as an engine folder on the same volume would), not into the root.
    char markerdir[PATH_MAX];
    snprintf(markerdir, sizeof markerdir, "%s%s", rootpath, outside ? "-markers" : "");
    if (outside && mkdir(markerdir, 0755) != 0 && errno != EEXIST) die("mkdir markers");
    sleep(1);
    start_stream2(rootpath, outside ? markerdir : NULL, latency, nodefer ? kFSEventStreamCreateFlagNoDefer : 0);
    sleep(1);
    FSEventStreamFlushSync(stream);
    clear_events();
    uint64_t t_setup_done = mach_absolute_time();

    uint64_t *line_start = calloc((size_t)rounds, sizeof *line_start); // before the first writer is spawned
    uint64_t *line_end = calloc((size_t)rounds, sizeof *line_end);  // all writers reaped
    uint64_t *ready = calloc((size_t)rounds, sizeof *ready);        // line-end procedure finished
    double *proc_ms = calloc((size_t)rounds, sizeof *proc_ms);
    int marker_seen = 0;
    char **logs = calloc((size_t)writers, sizeof *logs);
    size_t *loglens = calloc((size_t)writers, sizeof *loglens);

    for (int r = 0; r < rounds; r++) {
        line_start[r] = mach_absolute_time();
        pid_t *pids = calloc((size_t)writers, sizeof *pids);
        struct pollfd *pf = calloc((size_t)writers, sizeof *pf);
        for (int w = 0; w < writers; w++) {
            char dir[PATH_MAX], rs[16], os[16];
            snprintf(dir, sizeof dir, "%s/w%d", rootpath, w);
            snprintf(rs, sizeof rs, "%d", r);
            snprintf(os, sizeof os, "%d", ops);
            char *args[] = {"fsew", "writer", dir, rs, os, NULL};
            pids[w] = spawn_self(args, &pf[w].fd);
            pf[w].events = POLLIN;
            logs[w] = malloc(1 << 20);
            loglens[w] = 0;
        }
        // Drain every writer's pipe concurrently, so no writer blocks on a full pipe.
        for (int open_n = writers; open_n > 0;) {
            if (poll(pf, (nfds_t)writers, -1) < 0) die("poll");
            for (int w = 0; w < writers; w++) {
                if (pf[w].fd < 0 || !(pf[w].revents & (POLLIN | POLLHUP))) continue;
                ssize_t n = read(pf[w].fd, logs[w] + loglens[w], (1 << 20) - 1 - loglens[w]);
                if (n > 0) loglens[w] += (size_t)n;
                else {
                    close(pf[w].fd);
                    pf[w].fd = -1;
                    open_n--;
                }
            }
        }
        for (int w = 0; w < writers; w++) {
            int st;
            waitpid(pids[w], &st, 0);
            if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
                fprintf(stderr, "fsew: writer %d failed\n", w);
                exit(1);
            }
        }
        line_end[r] = mach_absolute_time();
        char marker[PATH_MAX];
        snprintf(marker, sizeof marker, "%s/line-end-%d", markerdir, r);
        int uses_marker = strcmp(proc, "marker") == 0 || strcmp(proc, "mflush") == 0 || strcmp(proc, "mloop") == 0;
        if (uses_marker) {
            arm_marker(marker);
            int fd = open(marker, O_WRONLY | O_CREAT, 0644);
            if (fd < 0) die("marker");
            close(fd);
        }
        if (strcmp(proc, "flush") == 0 || strcmp(proc, "mflush") == 0) {
            FSEventStreamFlushSync(stream);
        } else if (strcmp(proc, "marker") == 0 || strcmp(proc, "mloop") == 0) {
            wait_marker(strcmp(proc, "mloop") == 0); // mloop flushes before every look
        }
        ready[r] = mach_absolute_time();
        proc_ms[r] = ms_of(ready[r] - line_end[r]);
        if (uses_marker) marker_seen += marker_arrived();
        for (int w = 0; w < writers; w++) {
            logs[w][loglens[w]] = 0;
            parse_log(logs[w], r);
            free(logs[w]);
        }
        free(pids);
        free(pf);
    }
    sleep(3);
    FSEventStreamFlushSync(stream);
    stop_stream();

    // Match every expected operation to the first event for its path with the flag, delivered after setup.
    order = malloc(nevs * sizeof *order);
    for (size_t i = 0; i < nevs; i++) order[i] = i;
    qsort(order, nevs, sizeof *order, cmp_evpath);
    size_t on_time = 0, late = 0, missing = 0, last_total = 0, last_on_time = 0, last_late = 0, last_missing = 0;
    double *lat = malloc(nexps * sizeof *lat), *lat_last = malloc(nexps * sizeof *lat_last),
           *late_by = malloc(nexps * sizeof *late_by), *gap = malloc(nexps * sizeof *gap);
    size_t nlat = 0, nlat_last = 0, nlate_by = 0, ngap = 0;
    for (size_t i = 0; i < nexps; i++) {
        struct expect *e = &exps[i];
        e->match = find_match(e->path, e->bit, t_setup_done);
        if (e->last) {
            last_total++;
            gap[ngap++] = ms_of(line_end[e->round] - e->t);
        }
        if (e->match < 0) {
            missing++;
            last_missing += e->last;
            continue;
        }
        struct ev *v = &evs[e->match];
        double l = v->t > e->t ? ms_of(v->t - e->t) : -ms_of(e->t - v->t);
        lat[nlat++] = l;
        if (e->last) lat_last[nlat_last++] = l;
        if (v->t <= ready[e->round]) {
            on_time++;
            last_on_time += e->last;
        } else {
            late++;
            last_late += e->last;
            late_by[nlate_by++] = ms_of(v->t - ready[e->round]);
        }
    }
    // Rounds whose window (line start to the next line's start) saw a drop or rescan flag. FR-CKP-04 marks those
    // uncertain anyway; what matters is whether a round *without* any such flag is complete at line end.
    uint32_t drop_mask = kFSEventStreamEventFlagMustScanSubDirs | kFSEventStreamEventFlagUserDropped |
                         kFSEventStreamEventFlagKernelDropped;
    int *dropped = calloc((size_t)rounds, sizeof *dropped), ndropped = 0;
    for (size_t i = 0; i < nevs; i++) {
        if (!(evs[i].flags & drop_mask)) continue;
        for (int r = rounds - 1; r >= 0; r--)
            if (evs[i].t >= line_start[r]) {
                ndropped += !dropped[r];
                dropped[r] = 1;
                break;
            }
    }
    size_t clean_total = 0, clean_on_time = 0, clean_late = 0, clean_missing = 0;
    for (size_t i = 0; i < nexps; i++) {
        struct expect *e = &exps[i];
        if (dropped[e->round]) continue;
        clean_total++;
        if (e->match < 0) clean_missing++;
        else if (evs[e->match].t <= ready[e->round]) clean_on_time++;
        else clean_late++;
    }
    // Flags other than the item flags this run expects.
    size_t special = 0;
    uint32_t special_mask = kFSEventStreamEventFlagMustScanSubDirs | kFSEventStreamEventFlagUserDropped |
                            kFSEventStreamEventFlagKernelDropped | kFSEventStreamEventFlagEventIdsWrapped |
                            kFSEventStreamEventFlagRootChanged;
    for (size_t i = 0; i < nevs; i++) special += (evs[i].flags & special_mask) != 0;

    printf("config\twriters=%d\trounds=%d\tops_per_writer=%d\tlatency_s=%.3f\tprocedure=%s\tnodefer=%d\t"
           "marker=%s\n",
           writers, rounds, ops, latency, proc, nodefer, outside ? "outside_root" : "in_root");
    printf("expected\t%zu\ton_time\t%zu\tlate\t%zu\tmissing\t%zu\tmiss_rate_at_line_end\t%.5f\n", nexps, on_time,
           late, missing, nexps ? (double)(late + missing) / (double)nexps : 0);
    printf("last_ops\t%zu\ton_time\t%zu\tlate\t%zu\tmissing\t%zu\n", last_total, last_on_time, last_late,
           last_missing);
    printf("events_total\t%zu\tdrop_or_rescan_flags\t%zu\n", nevs, special);
    printf("rounds_with_drop_flags\t%d/%d\n", ndropped, rounds);
    printf("clean_rounds_ops\t%zu\ton_time\t%zu\tlate\t%zu\tmissing\t%zu\n", clean_total, clean_on_time,
           clean_late, clean_missing);
    if (strcmp(proc, "flush") != 0 && strcmp(proc, "none") != 0)
        printf("marker_seen_at_line_end\t%d/%d\n", marker_seen, rounds);
    dist("latency_ms_op_to_event", lat, nlat);
    dist("latency_ms_last_op_to_event", lat_last, nlat_last);
    dist("gap_ms_last_op_to_line_end", gap, ngap);
    dist("procedure_ms_line_end_to_ready", proc_ms, (size_t)rounds);
    dist("late_by_ms_after_ready", late_by, nlate_by);
    flag_histogram();
    // Up to 10 examples of late or missing operations.
    int shown = 0;
    for (size_t pass = 0; pass < 2; pass++)
    for (size_t i = 0; i < nexps && shown < 10; i++) {
        struct expect *e = &exps[i];
        if (e->match >= 0 && evs[e->match].t <= ready[e->round]) continue;
        if (dropped[e->round] != (int)pass) continue; // clean rounds first
        char fn[256];
        flagnames(e->bit, fn, sizeof fn);
        printf("example\tround=%d\tround_had_drop=%d\tflag=%s\tpath=%s\t%s\tlast=%d\n", e->round,
               dropped[e->round], fn, rel(e->path), e->match < 0 ? "missing" : "late", e->last);
        shown++;
    }
    return 0;
}

// ---- overflow ----------------------------------------------------------------------------------------------

static int burst(const char *dir, int ops) {
    char p[PATH_MAX];
    for (int k = 0; k < ops; k++) {
        snprintf(p, sizeof p, "%s/b-%d", dir, k);
        int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0 || write(fd, "x", 1) != 1) die("burst");
        close(fd);
        unlink(p);
    }
    return 0;
}

static void flag_histogram(void) {
    // Distinct flag combinations, with counts, and every event carrying a drop or rescan flag.
    uint32_t combos[256];
    size_t counts[256], nc = 0;
    for (size_t i = 0; i < nevs; i++) {
        size_t j = 0;
        while (j < nc && combos[j] != evs[i].flags) j++;
        if (j == nc && nc < 256) {
            combos[nc] = evs[i].flags;
            counts[nc++] = 0;
        }
        if (j < nc) counts[j]++;
    }
    char fn[512];
    for (size_t j = 0; j < nc; j++) {
        flagnames(combos[j], fn, sizeof fn);
        printf("flags\t%s\t%zu\n", fn, counts[j]);
    }
    uint32_t mask = kFSEventStreamEventFlagMustScanSubDirs | kFSEventStreamEventFlagUserDropped |
                    kFSEventStreamEventFlagKernelDropped | kFSEventStreamEventFlagRootChanged |
                    kFSEventStreamEventFlagEventIdsWrapped;
    size_t shown = 0;
    for (size_t i = 0; i < nevs && shown < 40; i++)
        if (evs[i].flags & mask) {
            flagnames(evs[i].flags, fn, sizeof fn);
            printf("special\tindex=%zu/%zu\tflags=%s\tpath=%s\tid=%llu\n", i, nevs, fn, rel(evs[i].path),
                   (unsigned long long)evs[i].id);
            shown++;
        }
}

static int overflow(int writers, int ops, int block_s) {
    char d[PATH_MAX];
    for (int w = 0; w < writers; w++) {
        snprintf(d, sizeof d, "%s/w%d", rootpath, w);
        if (mkdir(d, 0755) != 0 && errno != EEXIST) die("mkdir");
    }
    start_stream(rootpath, 0.0, 0);
    sleep(1);
    block_once_s = block_s;
    // A first event makes the callback run, and block.
    snprintf(d, sizeof d, "%s/trigger", rootpath);
    close(open(d, O_WRONLY | O_CREAT, 0644));
    usleep(300000);
    uint64_t t0 = mach_absolute_time();
    pid_t *pids = calloc((size_t)writers, sizeof *pids);
    for (int w = 0; w < writers; w++) {
        char dir[PATH_MAX], os[16];
        snprintf(dir, sizeof dir, "%s/w%d", rootpath, w);
        snprintf(os, sizeof os, "%d", ops);
        char *args[] = {"fsew", "burst", dir, os, NULL};
        int fd;
        pids[w] = spawn_self(args, &fd);
        close(fd);
    }
    for (int w = 0; w < writers; w++) waitpid(pids[w], NULL, 0);
    printf("config\twriters=%d\tops_per_writer=%d\tblock_s=%d\tburst_ms=%.0f\n", writers, ops, block_s,
           ms_of(mach_absolute_time() - t0));
    sleep((unsigned)block_s + 5);
    FSEventStreamFlushSync(stream);
    sleep(1);
    stop_stream();
    printf("events_total\t%zu\n", nevs);
    flag_histogram();
    return 0;
}

// ---- rootchange --------------------------------------------------------------------------------------------

static int rootchange(void) {
    char w[PATH_MAX], away[PATH_MAX];
    snprintf(w, sizeof w, "%s/watched", rootpath);
    snprintf(away, sizeof away, "%s/moved-away", rootpath);
    if (mkdir(w, 0755) != 0 && errno != EEXIST) die("mkdir");
    start_stream(w, 0.0, kFSEventStreamCreateFlagWatchRoot);
    sleep(1);
    if (rename(w, away) != 0) die("rename away");
    usleep(500000);
    FSEventStreamFlushSync(stream);
    if (rename(away, w) != 0) die("rename back");
    usleep(500000);
    FSEventStreamFlushSync(stream);
    stop_stream();
    char fn[512];
    for (size_t i = 0; i < nevs; i++) {
        flagnames(evs[i].flags, fn, sizeof fn);
        printf("event\tflags=%s\tpath=%s\n", fn, rel(evs[i].path));
    }
    return 0;
}

// ---- mmap --------------------------------------------------------------------------------------------------

static void print_events_for(const char *label, const char *path, size_t from) {
    char fn[512];
    pthread_mutex_lock(&evmu);
    int any = 0;
    for (size_t i = from; i < nevs; i++)
        if (strcmp(evs[i].path, path) == 0) {
            flagnames(evs[i].flags, fn, sizeof fn);
            printf("%s\tevent\tflags=%s\n", label, fn);
            any = 1;
        }
    if (!any) printf("%s\tno_event\n", label);
    pthread_mutex_unlock(&evmu);
}

// The line-end procedure that worked in `run`: create a marker, flush every millisecond until its event arrives.
static void settle_stream(void) {
    static int n;
    char m[PATH_MAX];
    snprintf(m, sizeof m, "%s/settle-%d", rootpath, n++);
    arm_marker(m);
    close(open(m, O_WRONLY | O_CREAT, 0644));
    wait_marker(1);
}

static int mmap_case(const char *label, int how, int settle) {
    char f[PATH_MAX];
    snprintf(f, sizeof f, "%s/%s.bin", rootpath, label);
    int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
    static char buf[1 << 20];
    memset(buf, 'A', sizeof buf);
    if (fd < 0 || write(fd, buf, sizeof buf) != (ssize_t)sizeof buf) die("mmap setup");
    fsync(fd);
    close(fd);
    sleep(1);
    settle_stream();
    size_t from = snapshot();
    int ready_pipe[2];
    if (pipe(ready_pipe) != 0) die("pipe");
    pid_t pid = fork();
    if (pid == 0) {
        int cfd = open(f, O_RDWR);
        if (how == 2) { // write(2) for comparison
            memset(buf, 'B', sizeof buf);
            _exit(pwrite(cfd, buf, sizeof buf, 0) == (ssize_t)sizeof buf ? 0 : 2);
        }
        char *m = mmap(NULL, sizeof buf, PROT_READ | PROT_WRITE, MAP_SHARED, cfd, 0);
        if (m == MAP_FAILED) _exit(2);
        memset(m, 'B', sizeof buf);
        if (how == 1 || how == 4) msync(m, sizeof buf, MS_SYNC);
        if (how == 3 || how == 4) {           // stay alive with the dirty mapping and the descriptor until killed
            close(ready_pipe[0]);
            if (write(ready_pipe[1], "r", 1) != 1) _exit(2);
            pause();
        }
        _exit(0); // no munmap, no close: the kernel tears both down at exit
    }
    if (how == 3 || how == 4) {
        char c;
        close(ready_pipe[1]);
        if (read(ready_pipe[0], &c, 1) != 1) die("alive writer");
        close(ready_pipe[0]);
        settle_stream();
        char la[128];
        snprintf(la, sizeof la, "%s.writer_alive", label);
        print_events_for(la, f, from);
        for (int t = 5; t <= settle; t += 5) {
            sleep(5);
            settle_stream();
            snprintf(la, sizeof la, "%s.writer_alive_%ds", label, t);
            print_events_for(la, f, from);
        }
        kill(pid, SIGKILL);
    }
    waitpid(pid, NULL, 0);
    if (how != 3 && how != 4) {
        close(ready_pipe[0]);
        close(ready_pipe[1]);
    }
    settle_stream();
    char l[128];
    snprintf(l, sizeof l, "%s.at_exit_flush", label);
    print_events_for(l, f, from);
    for (int t = 5; t <= settle; t += 5) {
        sleep(5);
        settle_stream();
        size_t n = 0;
        pthread_mutex_lock(&evmu);
        for (size_t i = from; i < nevs; i++) n += strcmp(evs[i].path, f) == 0;
        pthread_mutex_unlock(&evmu);
        printf("%s.after_%ds\tevents=%zu\n", label, t, n);
    }
    snprintf(l, sizeof l, "%s.final", label);
    print_events_for(l, f, from);
    return 0;
}

static int has_opt(int argc, char **argv, const char *opt) {
    for (int i = 8; i < argc; i++)
        if (strcmp(argv[i], opt) == 0) return 1;
    return 0;
}

int main(int argc, char **argv) {
    mach_timebase_info(&tb);
    setvbuf(stdout, NULL, _IOLBF, 0);
    uint32_t sz = sizeof self;
    if (_NSGetExecutablePath(self, &sz) != 0) die("executable path");
    if (argc >= 5 && strcmp(argv[1], "writer") == 0) return writer(argv[2], atoi(argv[3]), atoi(argv[4]));
    if (argc >= 4 && strcmp(argv[1], "burst") == 0) return burst(argv[2], atoi(argv[3]));
    if (argc < 3) {
        fprintf(stderr, "usage: see header\n");
        return 2;
    }
    if (realpath(argv[2], rootpath) == NULL) die("realpath");
    rootlen = strlen(rootpath);
    if (strcmp(argv[1], "run") == 0 && argc >= 8)
        return run(atoi(argv[3]), atoi(argv[4]), atoi(argv[5]), atof(argv[6]), argv[7],
                   has_opt(argc, argv, "nodefer"), has_opt(argc, argv, "outside"));
    if (strcmp(argv[1], "overflow") == 0 && argc >= 6)
        return overflow(atoi(argv[3]), atoi(argv[4]), atoi(argv[5]));
    if (strcmp(argv[1], "rootchange") == 0) return rootchange();
    if (strcmp(argv[1], "mmap") == 0) {
        int settle = argc > 3 ? atoi(argv[3]) : 40;
        start_stream(rootpath, 0.0, 0);
        sleep(1);
        mmap_case("mmap-nomsync", 0, settle);
        mmap_case("mmap-msync", 1, settle);
        mmap_case("pwrite", 2, 5);
        mmap_case("mmap-alive", 3, settle);
        mmap_case("mmap-msync-alive", 4, settle);
        stop_stream();
        return 0;
    }
    fprintf(stderr, "usage: see header\n");
    return 2;
}
