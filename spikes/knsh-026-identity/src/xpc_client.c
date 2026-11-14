// KNSH-026 C7 probe: the client side (stands in for the authority).
//
// Throwaway spike code (never shipped).
//
//   xpc_client <mach name> <tag> [--service-req <requirement>] [--exec <path>]
//   xpc_client --sleep <seconds>
//
// Connects to the Mach service, optionally requires the service to meet a code-signing
// requirement (FR-AUTH-15), sends {"tag": <tag>} and prints the reply or the XPC error.
// With --exec, it sends the message, waits until it has left (barrier), then execs <path>
// (passing --sleep 3), so the service sees the message's sender change identity.

#include <dispatch/dispatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <xpc/xpc.h>

static const char *xpc_error_name(xpc_object_t err) {
    if (err == XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT) return "PEER_CODE_SIGNING_REQUIREMENT";
    if (err == XPC_ERROR_CONNECTION_INVALID) return "CONNECTION_INVALID";
    if (err == XPC_ERROR_CONNECTION_INTERRUPTED) return "CONNECTION_INTERRUPTED";
    return "other";
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--sleep") == 0) {
        sleep((unsigned)atoi(argv[2]));
        return 0;
    }
    if (argc < 3) {
        fprintf(stderr, "usage: xpc_client <name> <tag> [--service-req R] [--exec PATH]\n");
        return 2;
    }
    const char *name = argv[1], *tag = argv[2], *service_req = NULL, *exec_path = NULL;
    for (int i = 3; i + 1 < argc; i += 2) {
        if (strcmp(argv[i], "--service-req") == 0) service_req = argv[i + 1];
        if (strcmp(argv[i], "--exec") == 0) exec_path = argv[i + 1];
    }

    xpc_connection_t conn = xpc_connection_create_mach_service(name, NULL, 0);
    xpc_connection_set_event_handler(conn, ^(xpc_object_t ev) {
      if (ev == XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT) {
          printf("connection event: PEER_CODE_SIGNING_REQUIREMENT (service failed our requirement)\n");
          fflush(stdout);
      }
    });
    if (service_req) {
        int rc = xpc_connection_set_peer_code_signing_requirement(conn, service_req);
        if (rc != 0) {
            printf("set_peer_code_signing_requirement rc=%d\n", rc);
            return 2;
        }
    }
    xpc_connection_resume(conn);

    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(msg, "tag", tag);

    if (exec_path) {
        xpc_connection_send_message(conn, msg);
        dispatch_semaphore_t sent = dispatch_semaphore_create(0);
        xpc_connection_send_barrier(conn, ^{ dispatch_semaphore_signal(sent); });
        dispatch_semaphore_wait(sent, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
        printf("sent; exec %s\n", exec_path);
        fflush(stdout);
        char *args[] = {(char *)exec_path, "--sleep", "3", NULL};
        execv(exec_path, args);
        perror("execv");
        return 1;
    }

    xpc_object_t reply = xpc_connection_send_message_with_reply_sync(conn, msg);
    if (xpc_get_type(reply) == XPC_TYPE_DICTIONARY) {
        printf("reply verdict=%s why=%s server=%s\n", xpc_dictionary_get_string(reply, "verdict"),
               xpc_dictionary_get_string(reply, "why"), xpc_dictionary_get_string(reply, "server"));
        return strcmp(xpc_dictionary_get_string(reply, "verdict"), "accept") == 0 ? 0 : 1;
    }
    printf("error %s\n", xpc_error_name(reply));
    return 1;
}
