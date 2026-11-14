// KNSH-026 C7 probe: the service side of an XPC Mach service with peer code-signing checks.
//
// Throwaway spike code (never shipped). Stands in for knshd's control service.
//
//   xpc_service <mach name> <log file> <mode> <client requirement> <min version>
//     mode: xpc     set xpc_connection_set_peer_code_signing_requirement on each peer
//                   (macOS 12+), then also check flags and version from the message
//           secode  no XPC-level requirement: check every message with
//                   SecCodeCreateWithXPCMessage (audit token) + SecCodeCheckValidity
//           listen  not under launchd: try to create the listener and report what happens
//
// Environment: DELAY_MS delays the handling of each message (lets a client exec first).
//
// Every message is also checked the unsafe way, by pid (SecCodeCopyGuestWithAttributes with
// the pid), and both results are logged, to show why the pid must not be used.
//
// The reply carries verdict=accept|reject and the reason. The full decision is knshd's
// (FR-AUTH-13, FR-AUTH-14): requirement met, hardened runtime, not debuggable, version >= min.

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <dispatch/dispatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <xpc/xpc.h>

// Code-signing flags from the kernel's <kern/cs_blobs.h> (not in the SDK's user headers).
#define CS_ADHOC 0x2
#define CS_GET_TASK_ALLOW 0x4
#define CS_RUNTIME 0x10000
#define CS_DEBUGGED 0x10000000

static FILE *out;
static const char *mode, *client_req_text, *min_version;
static SecRequirementRef client_req;
static char server_name[160];

// Names the well-known XPC errors; anything else is reported by its description string.
static const char *xpc_error_name(xpc_object_t ev) {
    if (ev == XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT) return "PEER_CODE_SIGNING_REQUIREMENT";
    if (ev == XPC_ERROR_CONNECTION_INVALID) return "CONNECTION_INVALID";
    if (ev == XPC_ERROR_CONNECTION_INTERRUPTED) return "CONNECTION_INTERRUPTED";
    if (ev == XPC_ERROR_TERMINATION_IMMINENT) return "TERMINATION_IMMINENT";
    const char *d = xpc_dictionary_get_string(ev, XPC_ERROR_KEY_DESCRIPTION);
    return d ? d : "unknown";
}

static void cfcopy(CFStringRef s, char *buf, size_t n) {
    buf[0] = 0;
    if (s && CFGetTypeID(s) == CFStringGetTypeID()) {
        CFStringGetCString(s, buf, (CFIndex)n, kCFStringEncodingUTF8);
    }
}

// Dotted numeric comparison: "1.10" > "1.9". Missing parts count as 0.
static int vercmp(const char *a, const char *b) {
    while (*a || *b) {
        long x = strtol(a, (char **)&a, 10), y = strtol(b, (char **)&b, 10);
        if (x != y) {
            return x < y ? -1 : 1;
        }
        if (*a == '.') a++;
        if (*b == '.') b++;
        if (!*a && !*b) break;
    }
    return 0;
}

struct facts {
    OSStatus create, valid;  // SecCode lookup, requirement check
    char ident[128], version[32];
    uint32_t cs_status;      // dynamic code-signing status of the live process
    uint32_t sig_flags;      // flags in the signature itself (CS_RUNTIME, CS_ADHOC)
};

// Gathers what a check needs from a SecCode: requirement result, identifier, flags, live
// status and the bundle version bound into the signature (Info.plist).
static void inspect(SecCodeRef code, OSStatus create, struct facts *f) {
    memset(f, 0, sizeof *f);
    f->create = create;
    f->valid = -1;
    if (create != errSecSuccess || !code) {
        return;
    }
    f->valid = SecCodeCheckValidity(code, kSecCSDefaultFlags, client_req);
    CFDictionaryRef info = NULL;
    if (SecCodeCopySigningInformation(code, kSecCSSigningInformation | kSecCSDynamicInformation |
                                                kSecCSRequirementInformation,
                                      &info) == errSecSuccess) {
        cfcopy(CFDictionaryGetValue(info, kSecCodeInfoIdentifier), f->ident, sizeof f->ident);
        CFNumberRef n = CFDictionaryGetValue(info, kSecCodeInfoStatus);
        if (n) CFNumberGetValue(n, kCFNumberSInt32Type, &f->cs_status);
        n = CFDictionaryGetValue(info, kSecCodeInfoFlags);
        if (n) CFNumberGetValue(n, kCFNumberSInt32Type, &f->sig_flags);
        CFDictionaryRef plist = CFDictionaryGetValue(info, kSecCodeInfoPList);
        if (plist) cfcopy(CFDictionaryGetValue(plist, CFSTR("CFBundleVersion")), f->version, sizeof f->version);
        CFRelease(info);
    }
}

// knshd's decision: every condition must hold; the first failure is the reason.
static const char *decide(const struct facts *f) {
    if (f->create != errSecSuccess) return "no-code-for-sender";
    if (f->valid != errSecSuccess) return "requirement-not-met";
    if (!(f->sig_flags & CS_RUNTIME)) return "no-hardened-runtime";
    if (f->cs_status & (CS_GET_TASK_ALLOW | CS_DEBUGGED)) return "debuggable";
    if (!f->version[0]) return "no-version";
    if (vercmp(f->version, min_version) < 0) return "below-min-version";
    return NULL;
}

static void log_facts(const char *label, const struct facts *f) {
    fprintf(out, "  %s: create=%d valid=%d id=%s version=%s sig_flags=0x%x cs_status=0x%x\n", label,
            (int)f->create, (int)f->valid, f->ident[0] ? f->ident : "-", f->version[0] ? f->version : "-",
            f->sig_flags, f->cs_status);
}

static void handle_message(xpc_connection_t peer, xpc_object_t msg) {
    const char *delay = getenv("DELAY_MS");
    if (delay) usleep((useconds_t)atoi(delay) * 1000);

    pid_t pid = xpc_connection_get_pid(peer);
    const char *tag = xpc_dictionary_get_string(msg, "tag");
    fprintf(out, "message tag=%s pid=%d\n", tag ? tag : "-", pid);

    // Audit-token path: bound to the exact process instance that sent this message.
    SecCodeRef by_token = NULL;
    OSStatus st = SecCodeCreateWithXPCMessage(msg, kSecCSDefaultFlags, &by_token);
    struct facts tok;
    inspect(by_token, st, &tok);
    log_facts("by-audit-token", &tok);

    // Pid path (unsafe, logged for comparison only): whatever process holds the pid now, which
    // after an exec (or pid reuse) is no longer the code that sent the message.
    CFNumberRef npid = CFNumberCreate(NULL, kCFNumberIntType, &pid);
    const void *k[] = {kSecGuestAttributePid}, *v[] = {npid};
    CFDictionaryRef attrs = CFDictionaryCreate(NULL, k, v, 1, &kCFTypeDictionaryKeyCallBacks,
                                               &kCFTypeDictionaryValueCallBacks);
    SecCodeRef by_pid = NULL;
    st = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &by_pid);
    struct facts pf;
    inspect(by_pid, st, &pf);
    log_facts("by-pid (unsafe)", &pf);
    const char *pid_reason = decide(&pf);
    fprintf(out, "  pid-based decision would be: %s\n", pid_reason ? pid_reason : "accept");

    const char *reason = decide(&tok);
    fprintf(out, "  decision: %s\n", reason ? reason : "accept");
    fflush(out);

    xpc_object_t reply = xpc_dictionary_create_reply(msg);
    if (reply) {
        xpc_dictionary_set_string(reply, "verdict", reason ? "reject" : "accept");
        xpc_dictionary_set_string(reply, "why", reason ? reason : "ok");
        // Which job answered: lets the harness tell the real service from an impostor.
        xpc_dictionary_set_string(reply, "server", server_name);
        xpc_connection_send_message(peer, reply);
    }
    if (reason) {
        xpc_connection_cancel(peer); // fail closed: drop the connection
    }
    if (by_token) CFRelease(by_token);
    if (by_pid) CFRelease(by_pid);
}

static void new_peer(xpc_connection_t peer) {
    fprintf(out, "peer pid=%d euid=%d\n", xpc_connection_get_pid(peer), xpc_connection_get_euid(peer));
    if (strcmp(mode, "xpc") == 0) {
        int rc = xpc_connection_set_peer_code_signing_requirement(peer, client_req_text);
        fprintf(out, "  set_peer_code_signing_requirement rc=%d\n", rc);
    }
    fflush(out);
    xpc_connection_set_event_handler(peer, ^(xpc_object_t ev) {
      if (xpc_get_type(ev) == XPC_TYPE_DICTIONARY) {
          handle_message(peer, ev);
      } else if (xpc_get_type(ev) == XPC_TYPE_ERROR) {
          fprintf(out, "peer event: %s\n", xpc_error_name(ev));
          fflush(out);
      }
    });
    xpc_connection_resume(peer);
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: xpc_service <name> <log> xpc|secode|listen <requirement> <min version>\n");
        return 2;
    }
    out = fopen(argv[2], "a");
    if (!out) return 2;
    mode = argv[3];
    client_req_text = argv[4];
    min_version = argv[5];
    CFStringRef rt = CFStringCreateWithCString(NULL, client_req_text, kCFStringEncodingUTF8);
    OSStatus st = SecRequirementCreateWithString(rt, kSecCSDefaultFlags, &client_req);
    // The signing identifier of this binary, for the "server" field of replies.
    SecCodeRef self = NULL;
    CFDictionaryRef selfinfo = NULL;
    if (SecCodeCopySelf(kSecCSDefaultFlags, &self) == errSecSuccess &&
        SecCodeCopySigningInformation(self, kSecCSSigningInformation, &selfinfo) == errSecSuccess) {
        char id[128];
        cfcopy(CFDictionaryGetValue(selfinfo, kSecCodeInfoIdentifier), id, sizeof id);
        CFNumberRef n = CFDictionaryGetValue(selfinfo, kSecCodeInfoFlags);
        uint32_t flags = 0;
        if (n) CFNumberGetValue(n, kCFNumberSInt32Type, &flags);
        snprintf(server_name, sizeof server_name, "%s%s/pid%d", id, (flags & CS_ADHOC) ? "(adhoc)" : "", getpid());
    }
    fprintf(out, "service start server=%s pid=%d ppid=%d mode=%s requirement_parse=%d\n", server_name, getpid(), getppid(), mode, (int)st);
    fflush(out);
    if (st != errSecSuccess) return 2;

    xpc_connection_t listener =
        xpc_connection_create_mach_service(argv[1], NULL, XPC_CONNECTION_MACH_SERVICE_LISTENER);
    xpc_connection_set_event_handler(listener, ^(xpc_object_t ev) {
      if (xpc_get_type(ev) == XPC_TYPE_CONNECTION) {
          new_peer((xpc_connection_t)ev);
      } else {
          fprintf(out, "listener event: %s\n", xpc_error_name(ev));
          fflush(out);
          if (strcmp(mode, "listen") == 0) exit(1);
      }
    });
    xpc_connection_resume(listener);
    if (strcmp(mode, "listen") == 0) {
        // Outside launchd the listener has no service to check in with; give it 3 s.
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
          fprintf(out, "listener still alive after 3 s (no error event)\n");
          fflush(out);
          exit(0);
        });
    }
    dispatch_main();
}
