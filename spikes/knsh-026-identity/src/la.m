// KNSH-026 C6 probe: can a launchd user agent show the LocalAuthentication prompt?
//
// Throwaway spike code (never shipped). Usage:
//
//   la <out file> <timeout seconds> <policy> <reason text>
//     policy: owner      LAPolicyDeviceOwnerAuthentication (Touch ID, then password fallback)
//             bio        LAPolicyDeviceOwnerAuthenticationWithBiometrics (Touch ID only)
//             owner-noui as owner, with interactionNotAllowed set (must fail without UI)
//
// Writes "key=value" lines to <out file> (the probe usually runs under launchd, with no
// terminal): the security session's attributes, canEvaluatePolicy, then the outcome of
// evaluatePolicy and how long it took. If nobody answers within the timeout, the context is
// invalidated and the outcome is recorded as such: a timeout means a prompt was pending,
// which is different from an immediate error. Only a human can say what the prompt showed.

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/AuthSession.h>
#include <stdio.h>
#include <time.h>

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc < 5) {
            fprintf(stderr, "usage: la <out> <timeout s> owner|bio|owner-noui <reason>\n");
            return 2;
        }
        FILE *out = fopen(argv[1], "w");
        if (!out) {
            return 2;
        }
        setvbuf(out, NULL, _IOLBF, 0);
        int timeout = atoi(argv[2]);
        NSString *mode = @(argv[3]);
        NSString *reason = @(argv[4]);

        // Session attributes: does this process's security session have graphics access, and
        // was it established over the network (SSH)?
        SecuritySessionId sid = 0;
        SessionAttributeBits attrs = 0;
        OSStatus st = SessionGetInfo(callerSecuritySession, &sid, &attrs);
        fprintf(out, "session_status=%d session_id=%u attrs=0x%x graphic=%d remote=%d tty=%d\n", (int)st,
                (unsigned)sid, (unsigned)attrs, (attrs & sessionHasGraphicAccess) != 0,
                (attrs & sessionIsRemote) != 0, (attrs & sessionHasTTY) != 0);
        fprintf(out, "pid=%d ppid=%d\n", getpid(), getppid());

        LAContext *ctx = [[LAContext alloc] init];
        LAPolicy policy = [mode isEqualToString:@"bio"] ? LAPolicyDeviceOwnerAuthenticationWithBiometrics
                                                         : LAPolicyDeviceOwnerAuthentication;
        if ([mode isEqualToString:@"owner-noui"]) {
            ctx.interactionNotAllowed = YES;
        }
        NSError *err = nil;
        BOOL can = [ctx canEvaluatePolicy:policy error:&err];
        fprintf(out, "can_evaluate=%d can_error=%ld biometry_type=%ld\n", can, (long)err.code, (long)ctx.biometryType);

        dispatch_semaphore_t done = dispatch_semaphore_create(0);
        __block BOOL ok = NO;
        __block NSError *evalErr = nil;
        double t0 = now_ms();
        [ctx evaluatePolicy:policy
            localizedReason:reason
                      reply:^(BOOL success, NSError *e) {
                        ok = success;
                        evalErr = e;
                        dispatch_semaphore_signal(done);
                      }];
        long waited = dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, (int64_t)timeout * NSEC_PER_SEC));
        if (waited != 0) {
            fprintf(out, "timed_out=1 after_ms=%.0f\n", now_ms() - t0);
            [ctx invalidate];
            dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
        }
        fprintf(out, "success=%d error_domain=%s error_code=%ld elapsed_ms=%.0f\n", ok,
                evalErr ? evalErr.domain.UTF8String : "-", (long)evalErr.code, now_ms() - t0);
        if (evalErr) {
            fprintf(out, "error_text=%s\n", evalErr.localizedDescription.UTF8String);
        }
        fclose(out);
        return ok ? 0 : 1;
    }
}
