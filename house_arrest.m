#import <Foundation/Foundation.h>
#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <CoreFoundation/CoreFoundation.h>
#include "lockdown.h"
#import "LSApplicationProxy.h"

int sandbox_extension_issue_file(const char *domain, const char *path, int flags);
int sandbox_init(const char *profile, uint64_t flags, char **errorbuf);
int sandbox_extension_consume(int unknown); //sandbox_extension_issue_file return value must be passed
int sandbox_free_error(void); //must be called if sandbox_init returned non null error buffer
#define SANDBOX_NAMED		0x0001

//afc
typedef void *AFCServerContextRef;
typedef void *AFCConnectionRef;
AFCServerContextRef AFCCreateServerContext(void);
AFCConnectionRef AFCConnectionCreate(int unknown, int socket, int unknown2, int unknown3, void *context);
void AFCConnectionSetSecureContext(AFCConnectionRef connection, void *secureIOContext);
void AFCInitServerConnection(AFCConnectionRef connection);
void AFCServerConnectionSetFileCoordinationEnabled(AFCConnectionRef connection, BOOL enabled);
void AFCServerConnectionSetRespectDataProtectionClass(AFCConnectionRef connection, BOOL enabled);
void AFCConnectionSetIOTimeout(AFCConnectionRef connection, int timeout);
int AFCServeWithRoot(AFCConnectionRef connection, CFStringRef path);
void AFCFreeServerContext(AFCServerContextRef context);
void AFCConnectionSetContext(AFCConnectionRef connection, void *context);
void AFCConnectionClose(AFCConnectionRef connection);

void log_error(const char *title, const char *description) {
    if (title)
        syslog(3, "%s: %s", title, description);
    else
        syslog(3, "%s", description);
}

void send_error(lockdown_t lockdown_connection, CFStringRef error_name) {
    CFMutableDictionaryRef response;
    response = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (response) {
        CFDictionarySetValue(response, CFSTR("Error"), error_name);
        if (lockdown_send_message(lockdown_connection, response, 100))
            log_error("send_error", "Could not send error response to host.");
        CFRelease(response);
    } else {
        log_error("send_error", "Could not create error response dictionary.");
    }
}

void handle_vending(lockdown_t lockdown_connection, CFDictionaryRef message, int action) {
    CFStringRef appBundleIdentifier = CFDictionaryGetValue(message, CFSTR("Identifier"));
    if (appBundleIdentifier) {
        @autoreleasepool {
            LSApplicationProxy *application_proxy;
            application_proxy = [LSApplicationProxy applicationProxyForIdentifier:(__bridge NSString *)appBundleIdentifier placeholder:NO];
            if (application_proxy && [[application_proxy applicationType] isEqualToString:@"User"]) {
                NSURL *dataContainerURL;
                
                switch (action) {
                    case 1:
                        if (![application_proxy profileValidated]) {
                            log_error("handle_vending", "Only containers for xcode-installed apps (apps with validated profiles) can be queried... but we don't care, right?;)");
                            //send_error(lockdown_connection, CFSTR("InstallationLookupFailed"));
                            //return;
                        }
                        dataContainerURL = [application_proxy dataContainerURL];
                        break;
                        
                    case 2:
                        dataContainerURL = [application_proxy dataContainerURL];
                        dataContainerURL = [dataContainerURL URLByAppendingPathComponent:@"Documents"];
                        break;
                        
                    default:
                        log_error("vend_container", "Unknown action.");
                        exit(1); //fatal error
                }
                
                if (dataContainerURL) {
                    NSString *dataContainerPath = [dataContainerURL path];
                    struct stat container_stat;
                    if (stat([dataContainerPath UTF8String], &container_stat) == 0) {
                        if (S_ISDIR(container_stat.st_mode)) {
                            CFMutableDictionaryRef response;
                            response = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
                            if (response) {
                                CFDictionarySetValue(response, CFSTR("Status"), CFSTR("Complete"));
                                if (lockdown_send_message(lockdown_connection, response, 100) == 0) {
                                    int lockdown_socket = lockdown_get_socket(lockdown_connection);
                                    void *lockdown_secure_context = lockdown_get_securecontext(lockdown_connection);
                                    
                                    if (chdir([dataContainerPath UTF8String]) == -1) {
                                        log_error("vend_afc", "Could not chdir to the app container.");
                                        exit(1);
                                    }
                                    
                                    int file = sandbox_extension_issue_file("com.apple.sandbox.container", [dataContainerPath UTF8String], 0);
                                    if (!file) {
                                        log_error("vend_afc", "sandbox_extension_issue_file failed.");
                                        exit(1);
                                    }
                                    
                                    char *error = nil;
                                    if (sandbox_init("mobile-house-arrest", SANDBOX_NAMED, &error) <= -1) {
                                        log_error("vend_afc", "sandbox_init failed.");
                                        exit(1);
                                    }
                                    if (sandbox_extension_consume(file) <= -1) {
                                        log_error("vend_afc", "sandbox_extension_consume failed.");
                                        exit(1);
                                    }
                                    if (error) sandbox_free_error();
                                    
                                    if ((setgid(0x1F5) == -1) || (setuid(0x1F5) == -1)) {
                                        log_error("vend_afc", "Could not set gid/uid.");
                                        exit(1);
                                    }
                                    
                                    int option_value = 1;
                                    if (setsockopt(lockdown_socket, SOL_SOCKET, SO_NOSIGPIPE, &option_value, 4) == -1) {
                                        log_error("vend_afc", "Could not set SO_NOSIGPIPE socket option.");
                                        exit(1);
                                    }
                                    
                                    AFCServerContextRef context = AFCCreateServerContext();
                                    AFCConnectionRef connection = AFCConnectionCreate(0, lockdown_socket, 0, 0, context);
                                    if (!connection) {
                                        log_error("vend_afc", "Could not open the AFC connection.");
                                        exit(1);
                                    }
                                    AFCConnectionSetSecureContext(connection, lockdown_secure_context);
                                    AFCInitServerConnection(connection);
                                    AFCServerConnectionSetFileCoordinationEnabled(connection, true);
                                    AFCServerConnectionSetRespectDataProtectionClass(connection, true);
                                    AFCConnectionSetIOTimeout(connection, 0);//infinite?
                                    int ret = AFCServeWithRoot(connection, (__bridge CFStringRef)dataContainerPath);
                                    if (ret && (ret != -402636789)) {
                                        log_error("vend_afc", "AFCServeWithRoot failed.");
                                        exit(1);
                                    }
                                    AFCFreeServerContext(context);
                                    AFCConnectionSetContext(connection, nil);
                                    AFCConnectionClose(connection);
                                } else {
                                    log_error("send_status", "Could not send response to host.");
                                }
                            } else {
                                log_error("send_status", "Could not create response dictionary.");
                            }
                        } else {
                            log_error("handle_vending", "Container is not a directory.");
                            send_error(lockdown_connection, CFSTR("InvalidPath"));
                        }
                    } else {
                        log_error("handle_vending", "Could not stat container path.");
                        send_error(lockdown_connection, CFSTR("PathMissing"));
                    }
                } else {
                    log_error("handle_vending", "Could not lookup application container.");
                    send_error(lockdown_connection, CFSTR("MissingContainer"));
                }
            } else {
                log_error("handle_vending", "Could not lookup installed applications.");
                send_error(lockdown_connection, CFSTR("InstallationLookupFailed"));
            }
        }
    } else {
        log_error("handle_vending", "Could not extract identifier.");
        send_error(lockdown_connection, CFSTR("MissingIdentifier"));
    }
}

int main(int argc, char **argv) {
    lockdown_t lockdown_connection;
    CFDictionaryRef message;
    CFStringRef command;
    int ret;
    
    openlog("mobile_house_arrest", LOG_PID, LOG_DAEMON);
    
    if (!secure_lockdown_checkin(&lockdown_connection ,0 ,0)) {
        ret = lockdown_receive_message(lockdown_connection, (CFPropertyListRef *)&message);
        if (ret <= 0 && message && (CFGetTypeID(message) == CFDictionaryGetTypeID())) {
            command = CFDictionaryGetValue(message, CFSTR("Command"));
            if (command) {
                if      (CFEqual(command, CFSTR("VendContainer"))) {
                    handle_vending(lockdown_connection, message, 1);
                }
                else if (CFEqual(command, CFSTR("VendDocuments"))) {
                    handle_vending(lockdown_connection, message, 2);
                }
                else {
                    log_error("main", "Unknown command.");
                    send_error(lockdown_connection, CFSTR("UnknownCommand"));
                }
            } else {
                log_error("main", "No command in request.");
                send_error(lockdown_connection, CFSTR("MissingCommand"));
            }
        } else {
            log_error("main", "Could not receive request from host.");
        }
        if (message) CFRelease(message);
        
        lockdown_disconnect(lockdown_connection);
    }
    
    return 0;
}
