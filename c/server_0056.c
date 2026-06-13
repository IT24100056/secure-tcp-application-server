#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <openssl/sha.h>

#define PORT 50056
#define SID "1000"
#define LOG_FILE "server_IT24100056.log"

typedef struct {
    char username[50];
    char salt[32];
    char password_hash[65];
} User;

typedef struct {
    char token[64];
    char username[50];
    time_t last_active;
} Session;

User users[100];
Session sessions[100];

int user_count = 0;
int session_count = 0;

void sigchld_handler(int sig){
    while(waitpid(-1,NULL,WNOHANG)>0);
}

void hash_password(const char *input, char *output){
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)input, strlen(input), hash);

    for(int i=0;i<SHA256_DIGEST_LENGTH;i++)
        sprintf(output+(i*2),"%02x",hash[i]);

    output[64]=0;
}

void generate_salt(char *salt){
    sprintf(salt,"%d",rand()%999999);
}

void generate_token(char *token){
    sprintf(token,"%ld_%d",time(NULL),rand());
}

int find_user(char *u){
    for(int i=0;i<user_count;i++)
        if(strcmp(users[i].username,u)==0)
            return i;
    return -1;
}

int find_session(char *t){
    for(int i=0;i<session_count;i++)
        if(strcmp(sessions[i].token,t)==0)
            return i;
    return -1;
}

void audit_log(struct sockaddr_in client,char *user,char *cmd,char *result){

    FILE *fp=fopen(LOG_FILE,"a");
    if(!fp) return;

    time_t now=time(NULL);
    char *t=ctime(&now);
    t[strcspn(t,"\n")]=0;

    fprintf(fp,
        "TIME:%s | IP:%s:%d | PID:%d | USER:%s | CMD:%s | RESULT:%s\n",
        t,
        inet_ntoa(client.sin_addr),
        ntohs(client.sin_port),
        getpid(),
        user?user:"N/A",
        cmd?cmd:"-",
        result?result:"-"
    );

    fclose(fp);
}

void register_user(char *u,char *p,int sock,struct sockaddr_in client){

    if(find_user(u)!=-1){
        send(sock,"ERR SID:1000 User exists\n",26,0);
        audit_log(client,u,"REGISTER","USER EXISTS");
        return;
    }

    User user;

    strcpy(user.username,u);
    generate_salt(user.salt);

    char temp[100];
    sprintf(temp,"%s%s",p,user.salt);

    hash_password(temp,user.password_hash);

    users[user_count++]=user;

    send(sock,"OK SID:1000 REGISTERED\n",24,0);

    audit_log(client,u,"REGISTER","SUCCESS");
}

void login_user(char *u,char *p,int sock,struct sockaddr_in client){

    int idx=find_user(u);

    if(idx==-1){
        send(sock,"ERR SID:1000 User not found\n",29,0);
        audit_log(client,u,"LOGIN","USER NOT FOUND");
        return;
    }

    char temp[100],hash[65];

    sprintf(temp,"%s%s",p,users[idx].salt);
    hash_password(temp,hash);

    if(strcmp(hash,users[idx].password_hash)!=0){
        send(sock,"ERR SID:1000 Wrong password\n",29,0);
        audit_log(client,u,"LOGIN","FAILED");
        return;
    }

    Session s;

    generate_token(s.token);
    strcpy(s.username,u);
    s.last_active=time(NULL);

    sessions[session_count++]=s;

    char resp[200];
    sprintf(resp,"OK SID:1000 TOKEN:%s\n",s.token);

    send(sock,resp,strlen(resp),0);

    audit_log(client,u,"LOGIN","SUCCESS");
}

void logout_user(char *token,int sock,struct sockaddr_in client){

    int idx=find_session(token);

    if(idx==-1){
        send(sock,"ERR SID:1000 Invalid token\n",28,0);
        audit_log(client,"N/A","LOGOUT","INVALID TOKEN");
        return;
    }

    sessions[idx]=sessions[session_count-1];
    session_count--;

    send(sock,"OK SID:1000 LOGGED OUT\n",24,0);

    audit_log(client,"N/A","LOGOUT","SUCCESS");
}

void handle_client(int sock,struct sockaddr_in client){

    char buffer[1024];

    while(1){

        int bytes=recv(sock,buffer,sizeof(buffer)-1,0);

        if(bytes<=0) break;

        buffer[bytes]='\0';

        char u[50],p[50],t[100];

        if(sscanf(buffer,"REGISTER %s %s",u,p)==2)
            register_user(u,p,sock,client);

        else if(sscanf(buffer,"LOGIN %s %s",u,p)==2)
            login_user(u,p,sock,client);

        else if(sscanf(buffer,"LOGOUT %s",t)==1)
            logout_user(t,sock,client);

        else{
            send(sock,"ERR SID:1000 Invalid command\n",30,0);
            audit_log(client,"N/A",buffer,"INVALID COMMAND");
        }
    }

    audit_log(client,"N/A","DISCONNECT","CLIENT EXIT");

    close(sock);
    exit(0);
}

int main(){

    srand(time(NULL));

    int server_sock,client_sock;

    struct sockaddr_in server,client;

    socklen_t csize=sizeof(client);

    signal(SIGCHLD,sigchld_handler);

    server_sock=socket(AF_INET,SOCK_STREAM,0);

    server.sin_family=AF_INET;
    server.sin_addr.s_addr=INADDR_ANY;
    server.sin_port=htons(PORT);

    bind(server_sock,(struct sockaddr*)&server,sizeof(server));

    listen(server_sock,10);

    printf("Server running on port %d\n",PORT);

    while(1){

        client_sock=accept(server_sock,(struct sockaddr*)&client,&csize);

        if(fork()==0){

            close(server_sock);

            handle_client(client_sock,client);
        }
        else
            close(client_sock);
    }

    return 0;
}
