// KNSH-026 C5 probe: Keychain access control by code signature.
//
// Throwaway spike code (never shipped). One binary, signed in several ways by c5-keychain.sh,
// stands in for successive `knshd` builds and for an unrelated binary of the same user.
//
//   kc <op> <store> <service> <account> [value]
//     op:    add | read | update | delete | acl
//     store: legacy  file-based login keychain, default ACL (creator trusted)
//            legacy-strict  as legacy, but the item's Encrypt (write) ACL entry is also limited
//                    to the creating binary, instead of the default "any application" (run by
//                    hand, not by c5-keychain.sh: it did not stop overwrites, see strict_access)
//            dp      data-protection keychain, default access group
//            dp:<g>  data-protection keychain, access group <g>
//
// Prints one line: "<op> <store> status=<OSStatus> (<message>) <detail>". Never shows a dialog:
// user interaction is disabled, so a would-be "allow access" prompt comes back as an error
// instead of blocking the harness. On the legacy keychain that error is errSecAuthFailed
// (-25293, observed), not errSecInteractionNotAllowed: it means "this binary is not trusted and
// would need the user to click Allow", which is recorded as not readable.
//
// BUILD is a compile-time constant so that build 1 and build 2 have different code hashes,
// like two releases of knshd.

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef BUILD
#define BUILD 1
#endif

#define STR2(x) #x
#define STR(x) STR2(x)
static const char *build_tag = "kc-build-" STR(BUILD);

// Spike code: the CF objects below are never released; each process runs one operation.
static CFStringRef cfs(const char *s) {
    return CFStringCreateWithCString(NULL, s, kCFStringEncodingUTF8);
}

static CFDataRef cfdata(const char *s) {
    return CFDataCreate(NULL, (const UInt8 *)s, (CFIndex)strlen(s));
}

// Base query: generic password, identified by service and account, in the chosen store.
static CFMutableDictionaryRef base_query(const char *store, const char *service, const char *account) {
    CFMutableDictionaryRef q = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks,
                                                         &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(q, kSecAttrService, cfs(service));
    CFDictionarySetValue(q, kSecAttrAccount, cfs(account));
    if (strncmp(store, "dp", 2) == 0) {
        CFDictionarySetValue(q, kSecUseDataProtectionKeychain, kCFBooleanTrue);
        if (store[2] == ':') {
            CFDictionarySetValue(q, kSecAttrAccessGroup, cfs(store + 3));
        }
    }
    return q;
}

// Decodes the hex-encoded XML plist of a partition-list ACL entry into its "Partitions" values.
static const char *decode_hex_plist(const char *hex) {
    static char out[1024];
    size_t n = strlen(hex) / 2;
    UInt8 *bytes = malloc(n);
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        sscanf(hex + 2 * i, "%2x", &v);
        bytes[i] = (UInt8)v;
    }
    CFDataRef data = CFDataCreate(NULL, bytes, (CFIndex)n);
    free(bytes);
    CFPropertyListRef pl = CFPropertyListCreateWithData(NULL, data, 0, NULL, NULL);
    snprintf(out, sizeof out, "(undecodable)");
    if (pl && CFGetTypeID(pl) == CFDictionaryGetTypeID()) {
        CFArrayRef parts = CFDictionaryGetValue(pl, CFSTR("Partitions"));
        out[0] = 0;
        for (CFIndex i = 0; parts && i < CFArrayGetCount(parts); i++) {
            char one[128];
            CFStringGetCString(CFArrayGetValueAtIndex(parts, i), one, sizeof one, kCFStringEncodingUTF8);
            strlcat(out, i ? " " : "", sizeof out);
            strlcat(out, one, sizeof out);
        }
    }
    return out;
}

static void print_status(const char *op, const char *store, OSStatus st, const char *detail) {
    CFStringRef msg = SecCopyErrorMessageString(st, NULL);
    char buf[256] = "";
    if (msg) {
        CFStringGetCString(msg, buf, sizeof buf, kCFStringEncodingUTF8);
        CFRelease(msg);
    }
    printf("%s %s status=%d (%s) %s\n", op, store, (int)st, buf, detail ? detail : "");
}

// Not in the public headers, but exported by Security.framework (used by `security
// dump-keychain -a`). Spike only: shows the designated requirement a trusted-app entry holds.
extern OSStatus SecTrustedApplicationCopyRequirement(SecTrustedApplicationRef app, SecRequirementRef *req);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// Builds a legacy access object in which every ACL entry trusts only the calling binary,
// except the partition-ID and change-ACL entries. By default SecItemAdd leaves the Encrypt
// entry open to any application, which lets any binary of the user overwrite the value without
// a prompt (observed). Closing it did not stop overwrites either (observed, ad hoc).
static SecAccessRef strict_access(void) {
    SecTrustedApplicationRef self = NULL;
    if (SecTrustedApplicationCreateFromPath(NULL, &self) != errSecSuccess) {
        return NULL;
    }
    CFArrayRef apps = CFArrayCreate(NULL, (const void **)&self, 1, &kCFTypeArrayCallBacks);
    SecAccessRef access = NULL;
    if (SecAccessCreate(CFSTR("knsh spike 026"), apps, &access) != errSecSuccess) {
        return NULL;
    }
    CFArrayRef acls = NULL;
    SecAccessCopyACLList(access, &acls);
    for (CFIndex i = 0; acls && i < CFArrayGetCount(acls); i++) {
        SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(acls, i);
        CFArrayRef cur = NULL;
        CFStringRef desc = NULL;
        SecKeychainPromptSelector sel = 0;
        SecACLCopyContents(acl, &cur, &desc, &sel);
        CFArrayRef auths = SecACLCopyAuthorizations(acl);
        bool partition = false, change_acl = false;
        for (CFIndex j = 0; auths && j < CFArrayGetCount(auths); j++) {
            CFStringRef a = CFArrayGetValueAtIndex(auths, j);
            partition |= CFEqual(a, kSecACLAuthorizationPartitionID);
            change_acl |= CFEqual(a, kSecACLAuthorizationChangeACL);
        }
        if (!partition && !change_acl) {
            SecACLSetContents(acl, apps, desc ? desc : CFSTR("knsh spike 026"), sel);
        }
    }
    return access;
}

static const char *apps_kind(CFArrayRef apps) {
    if (apps == NULL) {
        return "ANY";
    }
    return CFArrayGetCount(apps) == 0 ? "none" : "list";
}

// Dumps the legacy item's ACL: for each entry, its authorizations and its trusted
// applications' designated requirements, plus the partition list. Reading the ACL does not
// decrypt the item, so no prompt is involved.
static int dump_acl(const char *service, const char *account) {
    SecKeychainItemRef item = NULL;
    OSStatus st = SecKeychainFindGenericPassword(NULL, (UInt32)strlen(service), service,
                                                 (UInt32)strlen(account), account, NULL, NULL, &item);
    if (st != errSecSuccess) {
        print_status("acl", "legacy", st, "find");
        return 1;
    }
    SecAccessRef access = NULL;
    st = SecKeychainItemCopyAccess(item, &access);
    if (st != errSecSuccess) {
        print_status("acl", "legacy", st, "copy-access");
        return 1;
    }
    CFArrayRef acls = NULL;
    SecAccessCopyACLList(access, &acls);
    for (CFIndex i = 0; acls && i < CFArrayGetCount(acls); i++) {
        SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(acls, i);
        CFArrayRef apps = NULL;
        CFStringRef desc = NULL;
        SecKeychainPromptSelector sel = 0;
        SecACLCopyContents(acl, &apps, &desc, &sel);
        CFArrayRef auths = SecACLCopyAuthorizations(acl);
        char a[512] = "";
        for (CFIndex j = 0; auths && j < CFArrayGetCount(auths); j++) {
            char one[96];
            CFStringGetCString(CFArrayGetValueAtIndex(auths, j), one, sizeof one, kCFStringEncodingUTF8);
            strlcat(a, j ? "," : "", sizeof a);
            strlcat(a, one, sizeof a);
        }
        printf("acl[%ld] auth=%s apps=%s\n", (long)i, a, apps_kind(apps));
        for (CFIndex j = 0; apps && j < CFArrayGetCount(apps); j++) {
            SecTrustedApplicationRef app = (SecTrustedApplicationRef)CFArrayGetValueAtIndex(apps, j);
            SecRequirementRef req = NULL;
            CFStringRef text = NULL;
            if (SecTrustedApplicationCopyRequirement(app, &req) == errSecSuccess && req &&
                SecRequirementCopyString(req, kSecCSDefaultFlags, &text) == errSecSuccess) {
                char t[1024];
                CFStringGetCString(text, t, sizeof t, kCFStringEncodingUTF8);
                printf("  app[%ld] requirement: %s\n", (long)j, t);
            } else {
                printf("  app[%ld] requirement: (none: matched by path or hash)\n", (long)j);
            }
        }
        // The partition list entry stores its IDs as a hex-encoded plist in the description.
        if (desc && strstr(a, "PartitionID")) {
            char d[4096];
            CFStringGetCString(desc, d, sizeof d, kCFStringEncodingUTF8);
            printf("  partition list: %s\n", decode_hex_plist(d));
        }
    }
    return 0;
}

#pragma clang diagnostic pop

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: kc add|read|update|delete|acl <store> <service> <account> [value]\n");
        return 2;
    }
    const char *op = argv[1], *store = argv[2], *service = argv[3], *account = argv[4];
    const char *value = argc > 5 ? argv[5] : build_tag;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    // Legacy keychain: turn a would-be "allow access" dialog into an error (-25293, observed).
    SecKeychainSetUserInteractionAllowed(false);
#pragma clang diagnostic pop

    if (strcmp(op, "acl") == 0) {
        return dump_acl(service, account);
    }

    CFMutableDictionaryRef q = base_query(store, service, account);
    OSStatus st;
    char detail[256] = "";
    if (strcmp(op, "add") == 0) {
        CFDictionarySetValue(q, kSecValueData, cfdata(value));
        if (strcmp(store, "legacy-strict") == 0) {
            SecAccessRef access = strict_access();
            if (access == NULL) {
                print_status(op, store, errSecParam, "strict-access");
                return 1;
            }
            CFDictionarySetValue(q, kSecAttrAccess, access);
        }
        st = SecItemAdd(q, NULL);
        snprintf(detail, sizeof detail, "value=%s", value);
    } else if (strcmp(op, "read") == 0) {
        CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
        CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
        CFTypeRef out = NULL;
        st = SecItemCopyMatching(q, &out);
        if (st == errSecSuccess && out) {
            CFIndex n = CFDataGetLength(out);
            snprintf(detail, sizeof detail, "value=%.*s", (int)n, (const char *)CFDataGetBytePtr(out));
        }
    } else if (strcmp(op, "update") == 0) {
        CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(
            NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(attrs, kSecValueData, cfdata(value));
        st = SecItemUpdate(q, attrs);
        snprintf(detail, sizeof detail, "value=%s", value);
    } else if (strcmp(op, "delete") == 0) {
        st = SecItemDelete(q);
    } else {
        fprintf(stderr, "unknown op %s\n", op);
        return 2;
    }
    print_status(op, store, st, detail);
    return st == errSecSuccess ? 0 : 1;
}
