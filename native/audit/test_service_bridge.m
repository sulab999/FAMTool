// Read-only preflight test: never registers services, elevates or opens Settings.
#include "service_bridge.m"
#include <assert.h>
int main(void){@autoreleasepool{
    char *text=wj_audit_service_operation("preflight");assert(text);
    NSData *data=[NSData dataWithBytes:text length:strlen(text)];
    NSDictionary *result=[NSJSONSerialization JSONObjectWithData:data options:0 error:nil];wj_audit_service_free(text);
    assert(([@[@"invalid_bundle",@"signing_required",@"unsupported"] containsObject:result[@"state"]]));
    assert(![result[@"state"] isEqual:@"enabled"]);
    puts("Service authorization preflight rejected unapproved test binary; no privilege prompt issued.");return 0;
}}
