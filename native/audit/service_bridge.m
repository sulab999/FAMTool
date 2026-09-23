#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <ServiceManagement/ServiceManagement.h>
#import "code_identity.h"

static NSDictionary *answer(NSString *state,NSString *message) {return @{@"state":state,@"message":message};}
static NSDictionary *preflight(void) {
    NSBundle *bundle=NSBundle.mainBundle;
    NSURL *helper=[bundle.bundleURL URLByAppendingPathComponent:@"Contents/MacOS/audit-helper"];
    NSURL *plist=[bundle.bundleURL URLByAppendingPathComponent:@"Contents/Library/LaunchDaemons/com.famtool.audit.plist"];
    if(![[NSFileManager defaultManager] fileExistsAtPath:helper.path] || ![[NSFileManager defaultManager] fileExistsAtPath:plist.path])return answer(@"invalid_bundle",@"请使用完整应用包；缺少系统审计服务文件。");
    NSDictionary *app=signed_info(bundle.bundleURL,@"com.famtool.app");
    NSDictionary *tool=signed_info(helper,@"com.famtool.audit");
    if(!app || !tool)return answer(@"signing_required",@"当前不是具备正式签名的发布版本。需要有效的 Apple 开发者签名及公证后，才能申请 root 后台服务授权。");
    NSString *appTeam=app[(__bridge NSString*)kSecCodeInfoTeamIdentifier],*helperTeam=tool[(__bridge NSString*)kSecCodeInfoTeamIdentifier];
    if(!appTeam.length || ![appTeam isEqualToString:helperTeam])return answer(@"signing_required",@"主应用和辅助程序必须由同一 Apple 开发者团队签名。");
    NSDictionary *entitlements=tool[(__bridge NSString*)kSecCodeInfoEntitlementsDict];
    if(![entitlements[@"com.apple.developer.endpoint-security.client"] isEqual:@YES])return answer(@"entitlement_required",@"辅助程序缺少 Endpoint Security 专用 entitlement。此授权需向 Apple 申请，管理员密码不能替代。");
    return answer(@"eligible",@"签名与 entitlement 预检查通过；系统仍会验证服务注册及审计权限。");
}
static NSDictionary *service_operation(NSString *operation) {
    if([operation isEqual:@"privacy"]){
        NSString *url=@"x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles";
        if(@available(macOS 13.0,*)){}else{url=@"x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles";}
        BOOL opened=[NSWorkspace.sharedWorkspace openURL:[NSURL URLWithString:url]];
        return answer(opened?@"privacy_opened":@"failed",opened?@"已打开完全磁盘访问设置，请由用户开启审计辅助程序的权限。":@"无法打开系统设置，请手动进入隐私与安全性。");
    }
    if(@available(macOS 13.0,*)){
        if([operation isEqual:@"preflight"])return preflight();
        if([operation isEqual:@"enable"]){NSDictionary *check=preflight();if(![check[@"state"] isEqual:@"eligible"])return check;}
        SMAppService *service=[SMAppService daemonServiceWithPlistName:@"com.famtool.audit.plist"];
        if([operation isEqual:@"status"]){
            switch(service.status){case SMAppServiceStatusEnabled:return answer(@"enabled",@"后台服务已获准由系统以 root 运行，正在等待审计连接。");case SMAppServiceStatusRequiresApproval:return answer(@"approval_required",@"需要管理员在系统设置的登录项/后台项目中批准文件监控服务。");case SMAppServiceStatusNotFound:return answer(@"not_found",@"系统未找到审计服务，请检查完整应用包。");default:return answer(@"not_registered",@"尚未注册系统审计后台服务。");}
        }
        if([operation isEqual:@"stop"]){NSError *error=nil;if(service.status!=SMAppServiceStatusNotRegistered && ![service unregisterAndReturnError:&error])return answer(@"failed",error.localizedDescription?:@"停用后台服务失败");return answer(@"stopped",@"系统审计后台服务已停用，不再由系统自动启动。");}
        if([operation isEqual:@"preflight"])return preflight();
        if([operation isEqual:@"enable"]){
            if(service.status==SMAppServiceStatusEnabled)return service_operation(@"status");
            if(service.status!=SMAppServiceStatusRequiresApproval){NSError *error=nil;if(![service registerAndReturnError:&error] && service.status!=SMAppServiceStatusRequiresApproval)return answer(@"failed",error.localizedDescription?:@"系统拒绝注册后台服务，请核对签名、公证及管理员授权。");}
            if(service.status==SMAppServiceStatusRequiresApproval)[SMAppService openSystemSettingsLoginItems];
            return service_operation(@"status");
        }
        return answer(@"failed",@"不支持的服务操作");
    }
    return answer(@"unsupported",@"自动 root 服务授权需要 macOS 13 或更高版本；较旧系统可使用手动辅助程序方式。");
}
char *wj_audit_service_operation(const char *operation){@autoreleasepool{
    NSMutableDictionary *result=[service_operation([NSString stringWithUTF8String:operation]?:@"") mutableCopy];
    result[@"helper_path"]=[NSBundle.mainBundle.bundleURL URLByAppendingPathComponent:@"Contents/MacOS/audit-helper"].path;
    NSData *data=[NSJSONSerialization dataWithJSONObject:result options:0 error:nil];
    return strdup([[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding].UTF8String);
}}
void wj_audit_service_free(char *data){free(data);}
