// Native Endpoint Security NOTIFY-only collector. Never runs the WebView as root.
#import <Foundation/Foundation.h>
#import <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <pwd.h>
#include <signal.h>
#include <stdatomic.h>
#include <unistd.h>
#include <fcntl.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <Security/Security.h>

static volatile sig_atomic_t stopping = 0;
static _Atomic bool connected = false;
static _Atomic uint64_t dropped = 0;
static void stop_signal(int sig) { (void)sig; stopping=1; }
static NSString *token(es_string_token_t t) { return [[NSString alloc] initWithBytes:t.data length:t.length encoding:NSUTF8StringEncoding] ?: @""; }
static NSString *username(uid_t uid) {
    struct passwd pw, *result=NULL; char buffer[16384];
    if (getpwuid_r(uid,&pw,buffer,sizeof(buffer),&result)==0 && result) return [NSString stringWithUTF8String:pw.pw_name] ?: [@(uid) stringValue];
    return [@(uid) stringValue];
}
static NSString *object(mode_t mode) {return S_ISDIR(mode)?@"folder":S_ISREG(mode)?@"file":@"unknown";}
static NSDictionary *process_ref(audit_token_t audit) {
    pid_t pid=audit_token_to_pid(audit); if(pid<=0)return nil;
    NSMutableDictionary *p=[@{@"pid":@(pid),@"pid_version":@(audit_token_to_pidversion(audit))} mutableCopy];
    char path[PROC_PIDPATHINFO_MAXSIZE]={0};
    // Token-aware lookup prevents PID reuse from assigning a different process.
    if(proc_pidpath_audittoken(&audit,path,sizeof(path))>0) p[@"executable"]=[NSString stringWithUTF8String:path] ?: @"";
    return p;
}
static BOOL send_json(int fd, NSDictionary *value) {
    NSData *data=[NSJSONSerialization dataWithJSONObject:value options:0 error:nil];
    if(!data || data.length>65535)return NO;
    NSMutableData *frame=[data mutableCopy];[frame appendBytes:"\n" length:1];
    const uint8_t *bytes=frame.bytes;size_t left=frame.length;
    while(left>0){ssize_t n=send(fd,bytes,left,0);if(n<0 && errno==EINTR)continue;if(n<=0){atomic_store(&connected,false);return NO;}bytes+=n;left-=n;}
    return YES;
}
static NSDictionary *status(NSString *state,NSString *message) {return @{@"type":@"status",@"protocol":@1,@"state":state,@"message":message};}
static NSDictionary *es_error(es_new_client_result_t code) {
    switch(code){
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:return status(@"not_entitled",@"辅助程序缺少 Apple 批准的 Endpoint Security entitlement；临时签名不能授予此权限。");
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:return status(@"not_permitted",@"需要在系统设置中授予审计辅助程序完全磁盘访问权限。");
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:return status(@"not_privileged",@"审计辅助程序必须由管理员以 root 运行，主界面应保持普通用户权限。");
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:return status(@"too_many_clients",@"系统 Endpoint Security 客户端数量已达上限。");
        default:return status(@"failed",[NSString stringWithFormat:@"Endpoint Security 初始化失败，代码 %d",code]);
    }
}
static BOOL path_in(NSString *path,NSString *root) {return [path isEqualToString:root] || [path hasPrefix:[root isEqualToString:@"/"]?@"/":[root stringByAppendingString:@"/"]];}
static BOOL included(NSString *path,NSDictionary *scope) {
    if(![path hasPrefix:@"/"])return NO;
    for(NSString *exclude in scope[@"excludes"])if(path_in(path,exclude))return NO;
    for(NSString *root in scope[@"roots"])if(path_in(path,root) && ([scope[@"recursive"] boolValue] || [path isEqualToString:root] || [[path stringByDeletingLastPathComponent] isEqualToString:root]))return YES;
    return NO;
}
static NSDictionary *event_record(const es_message_t *msg,NSDictionary *scope) {
    if(msg->action_type!=ES_ACTION_TYPE_NOTIFY)return nil;
    if(msg->action.notify.result_type==ES_RESULT_TYPE_AUTH && msg->action.notify.result.auth==ES_AUTH_RESULT_DENY)return nil;
    NSString *event=nil,*path=nil,*from=nil,*kind=@"unknown";es_file_t *file=NULL;BOOL truncated=NO;
    switch(msg->event_type){
        case ES_EVENT_TYPE_NOTIFY_UNLINK:file=msg->event.unlink.target;event=@"removed";break;
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            if(!msg->event.close.modified)return nil;
            file=msg->event.close.target;event=@"modified";break;
        case ES_EVENT_TYPE_NOTIFY_OPEN:if(![scope[@"track_access"] boolValue])return nil;file=msg->event.open.file;event=@"accessed";break;
        case ES_EVENT_TYPE_NOTIFY_CREATE:
            // NEW_PATH can represent a denied create; never claim it succeeded.
            if(msg->event.create.destination_type!=ES_DESTINATION_TYPE_EXISTING_FILE)return nil;
            file=msg->event.create.destination.existing_file;event=@"created";break;
        case ES_EVENT_TYPE_NOTIFY_RENAME:{
            file=msg->event.rename.source;from=token(file->path);event=@"renamed";
            if(msg->event.rename.destination_type==ES_DESTINATION_TYPE_EXISTING_FILE){path=token(msg->event.rename.destination.existing_file->path);truncated=msg->event.rename.destination.existing_file->path_truncated;}
            else if(msg->event.rename.destination_type==ES_DESTINATION_TYPE_NEW_PATH){path=[token(msg->event.rename.destination.new_path.dir->path) stringByAppendingPathComponent:token(msg->event.rename.destination.new_path.filename)];truncated=msg->event.rename.destination.new_path.dir->path_truncated;}
            else return nil;
            break;
        }
        default:return nil;
    }
    if(!file)return nil;
    if(!path)path=token(file->path);truncated|=file->path_truncated;kind=object(file->stat.st_mode);
    if(!included(path,scope) && !(from && included(from,scope)))return nil;
    const es_process_t *p=msg->process;audit_token_t audit=p->audit_token;
    NSMutableDictionary *evidence=[@{
        @"event_type":@(msg->event_type),@"pid":@(audit_token_to_pid(audit)),@"pid_version":@(audit_token_to_pidversion(audit)),
        @"executable":token(p->executable->path),@"uid":@(audit_token_to_euid(audit)),@"real_uid":@(audit_token_to_ruid(audit)),@"audit_uid":@(audit_token_to_auid(audit)),
        @"signing_id":token(p->signing_id),@"team_id":token(p->team_id),@"sequence":@(msg->version>=2?msg->seq_num:0),@"global_sequence":@(msg->version>=4?msg->global_seq_num:0),@"mach_time":@(msg->mach_time)
    } mutableCopy];
    if(msg->version>=4){NSDictionary *parent=process_ref(p->parent_audit_token),*responsible=process_ref(p->responsible_audit_token);if(parent)evidence[@"parent"]=parent;if(responsible)evidence[@"responsible"]=responsible;}
    else if(p->ppid>0)evidence[@"parent"]=@{@"pid":@(p->ppid)};
    NSMutableDictionary *record=[@{@"type":@"event",@"protocol":@1,@"time_ms":@((int64_t)msg->time.tv_sec*1000+msg->time.tv_nsec/1000000),@"event":event,@"path":path,@"object":kind,@"user":username(audit_token_to_euid(audit)),@"owner":username(file->stat.st_uid),@"path_truncated":@(truncated),@"audit":evidence} mutableCopy];
    if(from)record[@"from"]=from;
    return record;
}
static NSDictionary *read_scope(int fd) {
    NSMutableData *data=[NSMutableData data];char c;
    while(data.length<65536){ssize_t n=recv(fd,&c,1,0);if(n<0 && errno==EINTR)continue;if(n!=1)return nil;if(c=='\n')break;[data appendBytes:&c length:1];}
    id value=[NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if(![value isKindOfClass:[NSDictionary class]] || ![value[@"protocol"] isEqual:@1])return nil;
    for(NSString *key in @[@"roots",@"excludes"]){if(![value[key] isKindOfClass:[NSArray class]] || [value[key] count]>1024)return nil;for(id p in value[key])if(![p isKindOfClass:[NSString class]]||![p hasPrefix:@"/"])return nil;}
    return value;
}
// Resolve only the active console user's owned, bounded rendezvous document.
static uid_t console_user(void) {
    uid_t uid=0;gid_t gid=0;CFStringRef name=SCDynamicStoreCopyConsoleUser(NULL,&uid,&gid);
    if(name)CFRelease(name);return uid;
}
static NSString *managed_socket(uid_t *uid) {
    *uid=console_user();if(*uid==0 || *uid==(uid_t)-1)return nil;
    struct passwd pw,*result=NULL;char buffer[16384];
    if(getpwuid_r(*uid,&pw,buffer,sizeof(buffer),&result)!=0 || !result)return nil;
    NSString *home=[NSString stringWithUTF8String:pw.pw_dir];if(![home hasPrefix:@"/"])return nil;
    NSString *file=[home stringByAppendingPathComponent:@"Library/Application Support/famtool/audit-endpoint.json"];
    int fd=open(file.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);if(fd<0)return nil;
    struct stat st;char bytes[8192];
    if(fstat(fd,&st)!=0 || !S_ISREG(st.st_mode)||st.st_uid!=*uid||(st.st_mode&0077)!=0||st.st_size<=0||st.st_size>=(off_t)sizeof(bytes)){close(fd);return nil;}
    ssize_t n=read(fd,bytes,(size_t)st.st_size);close(fd);if(n!=st.st_size)return nil;
    id value=[NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:bytes length:(NSUInteger)n] options:0 error:nil];
    if(![value isKindOfClass:[NSDictionary class]]||![value[@"protocol"] isEqual:@1]||![value[@"uid"] isEqual:@(*uid)]||![value[@"socket"] isKindOfClass:[NSString class]])return nil;
    NSString *path=value[@"socket"];return [path hasPrefix:@"/"]?path:nil;
}
static BOOL managed_peer(int fd) {
    audit_token_t token; socklen_t size=sizeof(token);
    if(getsockopt(fd,SOL_LOCAL,LOCAL_PEERTOKEN,&token,&size)!=0 || size!=sizeof(token))return NO;
    SecCodeRef self=NULL,peer=NULL;CFDictionaryRef info=NULL;
    if(SecCodeCopySelf(kSecCSDefaultFlags,&self)!=errSecSuccess)return NO;
    OSStatus rc=SecCodeCopySigningInformation(self,kSecCSSigningInformation,&info);CFRelease(self);
    if(rc!=errSecSuccess)return NO;
    NSDictionary *metadata=CFBridgingRelease(info);NSString *team=metadata[(__bridge NSString*)kSecCodeInfoTeamIdentifier];
    if(!team.length || [team rangeOfCharacterFromSet:NSCharacterSet.alphanumericCharacterSet.invertedSet].location!=NSNotFound)return NO;
    NSDictionary *attrs=@{(__bridge NSString*)kSecGuestAttributeAudit:[NSData dataWithBytes:&token length:sizeof(token)]};
    if(SecCodeCopyGuestWithAttributes(NULL,(__bridge CFDictionaryRef)attrs,kSecCSDefaultFlags,&peer)!=errSecSuccess)return NO;
    NSString *rule=[NSString stringWithFormat:@"anchor apple generic and identifier \"com.famtool.app\" and certificate leaf[subject.OU] = \"%@\"",team];
    SecRequirementRef requirement=NULL;rc=SecRequirementCreateWithString((__bridge CFStringRef)rule,kSecCSDefaultFlags,&requirement);
    if(rc==errSecSuccess){rc=SecCodeCheckValidity(peer,kSecCSDefaultFlags,requirement);CFRelease(requirement);}CFRelease(peer);return rc==errSecSuccess;
}
static int connect_gui(const char *path,uid_t user) {
    struct stat st;if(lstat(path,&st)!=0 || !S_ISSOCK(st.st_mode) || st.st_uid!=user || (st.st_mode&0077)!=0)return -1;
    struct sockaddr_un address={0};address.sun_family=AF_UNIX;
    if(strlen(path)>=sizeof(address.sun_path))return -1;strlcpy(address.sun_path,path,sizeof(address.sun_path));
    int fd=socket(AF_UNIX,SOCK_STREAM,0);if(fd<0)return -1;
    int yes=1;setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&yes,sizeof(yes));struct timeval timeout={2,0};setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    if(connect(fd,(struct sockaddr*)&address,sizeof(address))!=0){close(fd);return -1;}
    uid_t uid;gid_t gid;if(getpeereid(fd,&uid,&gid)!=0||uid!=user){close(fd);return -1;}return fd;
}
int main(int argc,const char *argv[]) { @autoreleasepool {
    if(argc==2 && strcmp(argv[1],"--check")==0){es_client_t *client=NULL;es_new_client_result_t code=es_new_client(&client,^(es_client_t *c,const es_message_t *m){(void)c;(void)m;});NSDictionary *result=code==ES_NEW_CLIENT_RESULT_SUCCESS?status(@"ready",@"Endpoint Security 初始化检查通过"):es_error(code);NSData *data=[NSJSONSerialization dataWithJSONObject:result options:0 error:nil];fwrite(data.bytes,1,data.length,stdout);fputc('\n',stdout);if(client)es_delete_client(client);return code==ES_NEW_CLIENT_RESULT_SUCCESS?0:1;}
    BOOL managed=argc==2 && strcmp(argv[1],"--managed")==0;
    if(!managed && (argc!=5 || strcmp(argv[1],"--socket") || strcmp(argv[3],"--uid"))){fprintf(stderr,"Usage: famtool-audit --check | --managed | --socket /absolute/audit.sock --uid USER_ID\n");return 2;}
    char *end=NULL;unsigned long parsed=0;
    if(!managed){parsed=strtoul(argv[4],&end,10);if(!end||*end||parsed==0||parsed>UINT32_MAX||argv[2][0]!='/'){fprintf(stderr,"Invalid socket or target user ID\n");return 2;}}
    if(geteuid()!=0){fprintf(stderr,"The native audit collector requires root; do not run the GUI as root.\n");return 3;}
    signal(SIGINT,stop_signal);signal(SIGTERM,stop_signal);signal(SIGPIPE,SIG_IGN);
    uid_t user=(uid_t)parsed;
    while(!stopping){ @autoreleasepool {
        NSString *path=managed?managed_socket(&user):[NSString stringWithUTF8String:argv[2]];
        if(!path){sleep(1);continue;}
        int fd=connect_gui(path.fileSystemRepresentation,user);if(fd<0){sleep(1);continue;}
        if(managed && !managed_peer(fd)){close(fd);sleep(1);continue;}
        atomic_store(&connected,true);atomic_store(&dropped,0);
        if(!send_json(fd,@{@"type":@"hello",@"protocol":@1})){close(fd);continue;}
        NSDictionary *scope=read_scope(fd);if(!scope){close(fd);sleep(1);continue;}
        dispatch_queue_t queue=dispatch_queue_create("com.famtool.audit.writer",DISPATCH_QUEUE_SERIAL);
        dispatch_semaphore_t slots=dispatch_semaphore_create(512);
        __block uint64_t last_seq=0;__block BOOL seen_seq=NO;
        es_client_t *client=NULL;
        es_new_client_result_t code=es_new_client(&client,^(es_client_t *c,const es_message_t *message){
            (void)c;
            if(message->version>=4){if(seen_seq && message->global_seq_num>last_seq+1)atomic_fetch_add(&dropped,message->global_seq_num-last_seq-1);last_seq=message->global_seq_num;seen_seq=YES;}
            if(!atomic_load(&connected) || audit_token_to_pid(message->process->audit_token)==getpid())return;
            if(dispatch_semaphore_wait(slots,DISPATCH_TIME_NOW)!=0){atomic_fetch_add(&dropped,1);return;}
            es_retain_message(message);
            dispatch_async(queue,^{@autoreleasepool{if(atomic_load(&connected)){NSDictionary *record=event_record(message,scope);if(record)send_json(fd,record);}es_release_message(message);dispatch_semaphore_signal(slots);}});
        });
        if(code!=ES_NEW_CLIENT_RESULT_SUCCESS){send_json(fd,es_error(code));close(fd);return 4;}
        es_event_type_t events[]={ES_EVENT_TYPE_NOTIFY_UNLINK,ES_EVENT_TYPE_NOTIFY_RENAME,ES_EVENT_TYPE_NOTIFY_CREATE,ES_EVENT_TYPE_NOTIFY_CLOSE,ES_EVENT_TYPE_NOTIFY_OPEN};
        const es_event_type_t *event_types=events;
        __block es_return_t subscribed=ES_RETURN_ERROR;
        // The writer queue serializes ready BEFORE any queued notification, but
        // only publishes running AFTER es_subscribe succeeds.
        dispatch_sync(queue,^{
            subscribed=es_subscribe(client,event_types,[scope[@"track_access"] boolValue]?5:4);
            send_json(fd,subscribed==ES_RETURN_SUCCESS?status(@"running",@"原生 Endpoint Security 审计已连接"):status(@"failed",@"订阅系统审计事件失败"));
        });
        if(subscribed!=ES_RETURN_SUCCESS){es_delete_client(client);atomic_store(&connected,false);dispatch_sync(queue,^{});close(fd);return 5;}
        while(!stopping && atomic_load(&connected)){sleep(1);if(managed && console_user()!=user){atomic_store(&connected,false);break;}dispatch_async(queue,^{@autoreleasepool{if(atomic_load(&connected)){uint64_t lost=atomic_exchange(&dropped,0);send_json(fd,@{@"type":@"heartbeat",@"protocol":@1,@"dropped":@(lost)});}}});}
        es_unsubscribe_all(client);es_delete_client(client);atomic_store(&connected,false);dispatch_sync(queue,^{});close(fd);
    }}
    return 0;
}}
