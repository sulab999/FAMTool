// Shared signature policy. Managed privilege is never granted to ad-hoc code.
#import <Security/Security.h>
static BOOL apple_signed_code(SecStaticCodeRef code,NSString *identifier) {
    NSString *rule=[NSString stringWithFormat:@"anchor apple generic and identifier \"%@\"",identifier];
    SecRequirementRef requirement=NULL;
    if(SecRequirementCreateWithString((__bridge CFStringRef)rule,kSecCSDefaultFlags,&requirement)!=errSecSuccess)return NO;
    OSStatus result=SecStaticCodeCheckValidity(code,kSecCSCheckAllArchitectures,requirement);CFRelease(requirement);return result==errSecSuccess;
}
static NSDictionary *signed_info(NSURL *url,NSString *identifier) {
    SecStaticCodeRef code=NULL;CFDictionaryRef info=NULL;
    if(SecStaticCodeCreateWithPath((__bridge CFURLRef)url,kSecCSDefaultFlags,&code)!=errSecSuccess)return nil;
    BOOL valid=apple_signed_code(code,identifier);
    if(valid)valid=SecCodeCopySigningInformation(code,kSecCSSigningInformation,&info)==errSecSuccess;
    CFRelease(code);return valid?CFBridgingRelease(info):nil;
}
