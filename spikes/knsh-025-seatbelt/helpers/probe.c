/*
 * KNSH-025 spike probe (throwaway, never shipped).
 *
 * One binary, one subcommand per thing a Seatbelt rule must stop. Each subcommand prints a
 * single line "<name> ok ..." or "<name> fail errno=<n> (<text>)" and exits 0 on success,
 * 1 on failure, 2 on a usage error, so the shell harness can tabulate allowed vs denied.
 *
 *   probe procargs <pid>      sysctl KERN_PROCARGS2: argv and environment of <pid>
 *   probe pidinfo <pid>       proc_pidinfo PROC_PIDTASKALLINFO (what ps uses for state)
 *   probe pidpath <pid>       proc_pidpath
 *   probe listpids            proc_listpids(PROC_ALL_PIDS): count of visible pids
 *   probe kill <pid> <sig>    kill(2)
 *   probe killpg <pgid> <sig> killpg(2)
 *   probe connect <path>      connect(2) to a Unix stream socket
 *   probe lookup <service>    bootstrap_look_up: named Mach service lookup
 *   probe newpgrp <cmd...>    setpgid(0,0) then exec <cmd> (puts a process outside a group)
 *   probe child-signal        fork a child in our own group, signal it, report
 *   probe lsquery <bundle-id> LaunchServices database query (no app is opened)
 *   probe kproc <pid|all>     sysctl KERN_PROC_PID / KERN_PROC_ALL (kinfo_proc: what ps lists)
 *
 * Build: clang -Wall -O1 -o .build/probe helpers/probe.c -framework CoreServices
 */
#include <CoreServices/CoreServices.h>
#include <errno.h>
#include <libproc.h>
#include <servers/bootstrap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int fail(const char *name, int e) {
    printf("%s fail errno=%d (%s)\n", name, e, strerror(e));
    return 1;
}

/* The environment variable c8-rules.sh sets on its victim process. */
#define SECRET_PREFIX "KNSH_SPIKE_SECRET="

static int procargs(pid_t pid) {
    int mib[3] = {CTL_KERN, KERN_PROCARGS2, pid};
    size_t len = 0;
    if (sysctl(mib, 3, NULL, &len, NULL, 0) != 0) return fail("procargs", errno);
    char *buf = malloc(len);
    if (!buf) return fail("procargs", ENOMEM);
    if (sysctl(mib, 3, buf, &len, NULL, 0) != 0) {
        int e = errno;
        free(buf);
        return fail("procargs", e);
    }
    int argc;
    memcpy(&argc, buf, sizeof argc);
    /* Skip exec path and padding, then argv, then report how many environment strings follow. */
    char *p = buf + sizeof argc, *end = buf + len;
    p += strnlen(p, end - p);
    while (p < end && *p == '\0') p++;
    for (int i = 0; i < argc && p < end; i++) p += strnlen(p, end - p) + 1;
    int envc = 0, secret = 0;
    while (p < end && *p) {
        if (strncmp(p, SECRET_PREFIX, sizeof SECRET_PREFIX - 1) == 0) secret = 1;
        envc++;
        p += strnlen(p, end - p) + 1;
    }
    printf("procargs ok argc=%d envc=%d secret_visible=%d\n", argc, envc, secret);
    free(buf);
    return 0;
}

static int pidinfo(pid_t pid) {
    struct proc_taskallinfo ti;
    int n = proc_pidinfo(pid, PROC_PIDTASKALLINFO, 0, &ti, sizeof ti);
    if (n <= 0) return fail("pidinfo", errno ? errno : EPERM);
    printf("pidinfo ok comm=%s pgid=%u\n", ti.pbsd.pbi_comm, ti.pbsd.pbi_pgid);
    return 0;
}

static int pidpath(pid_t pid) {
    char path[PROC_PIDPATHINFO_MAXSIZE];
    if (proc_pidpath(pid, path, sizeof path) <= 0) return fail("pidpath", errno ? errno : EPERM);
    printf("pidpath ok %s\n", path);
    return 0;
}

static int listpids(void) {
    int n = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (n <= 0) return fail("listpids", errno ? errno : EPERM);
    printf("listpids ok count~%d\n", n / (int)sizeof(pid_t));
    return 0;
}

static int do_connect(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return fail("connect", errno);
    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    strlcpy(sa.sun_path, path, sizeof sa.sun_path);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        int e = errno;
        close(fd);
        return fail("connect", e);
    }
    printf("connect ok %s\n", path);
    close(fd);
    return 0;
}

static int lookup(const char *name) {
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, name, &port);
    if (kr != KERN_SUCCESS) {
        printf("lookup fail kr=%d (%s)\n", kr, bootstrap_strerror(kr));
        return 1;
    }
    printf("lookup ok %s\n", name);
    return 0;
}

static int lsquery(const char *bundle) {
    CFStringRef id = CFStringCreateWithCString(NULL, bundle, kCFStringEncodingUTF8);
    CFErrorRef err = NULL;
    CFArrayRef urls = LSCopyApplicationURLsForBundleIdentifier(id, &err);
    CFRelease(id);
    if (!urls) {
        long code = err ? (long)CFErrorGetCode(err) : 0;
        if (err) CFRelease(err);
        printf("lsquery fail code=%ld\n", code);
        return 1;
    }
    printf("lsquery ok apps=%ld\n", (long)CFArrayGetCount(urls));
    CFRelease(urls);
    return 0;
}

static int kproc(const char *which) {
    int all = !strcmp(which, "all");
    int mib[4] = {CTL_KERN, KERN_PROC, all ? KERN_PROC_ALL : KERN_PROC_PID, all ? 0 : atoi(which)};
    size_t len = 0;
    if (sysctl(mib, all ? 3 : 4, NULL, &len, NULL, 0) != 0) return fail("kproc", errno);
    /* KERN_PROC_PID of a pid the caller may not see returns success with zero length. */
    if (len == 0) return fail("kproc", ESRCH);
    printf("kproc ok entries=%zu\n", len / sizeof(struct kinfo_proc));
    return 0;
}

static int child_signal(void) {
    pid_t c = fork();
    if (c < 0) return fail("child-signal", errno);
    if (c == 0) {
        /* Close inherited output and bound our life: if the parent's kill is denied, nothing
         * else can reap us, and an open pipe would hang the harness. */
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        alarm(3);
        pause();
        _exit(0);
    }
    usleep(100000);
    int r = kill(c, SIGTERM);
    int e = errno;
    if (r != 0) {
        kill(c, SIGKILL); /* best effort; may also be denied */
        return fail("child-signal", e);
    }
    waitpid(c, NULL, 0);
    printf("child-signal ok\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    const char *cmd = argv[1];
    if (!strcmp(cmd, "procargs") && argc == 3) return procargs(atoi(argv[2]));
    if (!strcmp(cmd, "pidinfo") && argc == 3) return pidinfo(atoi(argv[2]));
    if (!strcmp(cmd, "pidpath") && argc == 3) return pidpath(atoi(argv[2]));
    if (!strcmp(cmd, "listpids")) return listpids();
    if (!strcmp(cmd, "kill") && argc == 4) {
        if (kill(atoi(argv[2]), atoi(argv[3])) != 0) return fail("kill", errno);
        printf("kill ok\n");
        return 0;
    }
    if (!strcmp(cmd, "killpg") && argc == 4) {
        if (killpg(atoi(argv[2]), atoi(argv[3])) != 0) return fail("killpg", errno);
        printf("killpg ok\n");
        return 0;
    }
    if (!strcmp(cmd, "connect") && argc == 3) return do_connect(argv[2]);
    if (!strcmp(cmd, "lookup") && argc == 3) return lookup(argv[2]);
    if (!strcmp(cmd, "child-signal")) return child_signal();
    if (!strcmp(cmd, "lsquery") && argc == 3) return lsquery(argv[2]);
    if (!strcmp(cmd, "kproc") && argc == 3) return kproc(argv[2]);
    if (!strcmp(cmd, "newpgrp") && argc >= 3) {
        if (setpgid(0, 0) != 0) return fail("newpgrp", errno);
        execv(argv[2], &argv[2]);
        return fail("newpgrp", errno);
    }
    return 2;
}
