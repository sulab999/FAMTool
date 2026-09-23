// Synthetic SDK message tests; these do NOT claim live kernel audit access.
#define main audit_program_main
#include "main.m"
#undef main
#include <assert.h>
static es_string_token_t string_token(const char *s){return (es_string_token_t){.length=strlen(s),.data=s};}
int main(void){@autoreleasepool{
    audit_token_t audit={0};mach_msg_type_number_t count=TASK_AUDIT_TOKEN_COUNT;
    assert(task_info(mach_task_self(),TASK_AUDIT_TOKEN,(task_info_t)&audit,&count)==KERN_SUCCESS);
    es_file_t executable={0},file={0},parent_dir={0};executable.path=string_token("/bin/rm");
    file.path=string_token("/watched/授权书_副本.png");file.stat.st_mode=S_IFREG|0600;file.stat.st_uid=getuid();parent_dir.path=string_token("/watched");
    es_process_t process={0};process.audit_token=audit;process.executable=&executable;process.parent_audit_token=audit;process.responsible_audit_token=audit;
    process.signing_id=string_token("com.apple.rm");process.team_id=string_token("");
    es_message_t msg={0};msg.version=4;msg.process=&process;msg.action_type=ES_ACTION_TYPE_NOTIFY;msg.action.notify.result_type=ES_RESULT_TYPE_AUTH;msg.action.notify.result.auth=ES_AUTH_RESULT_ALLOW;msg.event_type=ES_EVENT_TYPE_NOTIFY_UNLINK;msg.event.unlink.target=&file;msg.time.tv_sec=1700000000;msg.global_seq_num=7;
    NSDictionary *scope=@{@"roots":@[@"/watched"],@"excludes":@[@"/watched/private"],@"recursive":@YES,@"track_access":@NO};
    NSDictionary *record=event_record(&msg,scope);assert([record[@"event"] isEqual:@"removed"]);assert([record[@"path"] isEqual:@"/watched/授权书_副本.png"]);assert([record[@"audit"][@"executable"] isEqual:@"/bin/rm"]);assert([record[@"audit"][@"pid"] intValue]==getpid());assert([record[@"audit"][@"global_sequence"] intValue]==7);
    assert([NSJSONSerialization dataWithJSONObject:record options:0 error:nil]!=nil);
    msg.action.notify.result.auth=ES_AUTH_RESULT_DENY;assert(event_record(&msg,scope)==nil);msg.action.notify.result.auth=ES_AUTH_RESULT_ALLOW;
    file.path=string_token("/watched/private/a.png");assert(event_record(&msg,scope)==nil);file.path=string_token("/watched/old.png");
    msg.event_type=ES_EVENT_TYPE_NOTIFY_RENAME;msg.event.rename.source=&file;msg.event.rename.destination_type=ES_DESTINATION_TYPE_NEW_PATH;msg.event.rename.destination.new_path.dir=&parent_dir;msg.event.rename.destination.new_path.filename=string_token("授权书_副本.png");
    record=event_record(&msg,scope);assert([record[@"from"] isEqual:@"/watched/old.png"]);assert([record[@"path"] isEqual:@"/watched/授权书_副本.png"]);
    assert([es_error(ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED)[@"state"] isEqual:@"not_entitled"]);
    int peers[2];assert(socketpair(AF_UNIX,SOCK_STREAM,0,peers)==0);assert(!managed_peer(peers[0]));close(peers[0]);close(peers[1]);
    puts("Native audit encoder tests passed (synthetic messages, no ES authorization used).");return 0;
}}
