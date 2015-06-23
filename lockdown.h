#include <CoreFoundation/CoreFoundation.h>

typedef int lockdown_t;

int secure_lockdown_checkin(lockdown_t *conn, int unknown, int unknown1);
lockdown_t lockdown_connect();
void lockdown_disconnect(lockdown_t conn);
int lockdown_send_message(lockdown_t conn, CFPropertyListRef message, int flags);
int lockdown_receive_message(lockdown_t conn, CFPropertyListRef* message);
int lockdown_get_socket(lockdown_t conn);
void *lockdown_get_securecontext(lockdown_t conn);
