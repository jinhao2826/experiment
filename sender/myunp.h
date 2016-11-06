#include        <sys/types.h>
#include        <sys/socket.h>
#include	<netinet/in.h>
#include        <stdio.h>
#include        <string.h>
#include        <stdlib.h>
#include	<time.h>
#include	<syslog.h>
#include 	<stdarg.h>
#include 	<errno.h>
#include	<linux/ip.h>
#include	<netdb.h>

#define          MAXLINE    4096
#define          SA    struct sockaddr
#define         LISTENQ 1024
#define 	SERV_PORT 9877 


static int	read_cnt;
static char	*read_ptr;
static char	read_buf[MAXLINE];


void err_sys(const char* x) 
{ 
    perror(x); 
    exit(1); 
}



static ssize_t
my_read(int fd, char *ptr)
{

	if (read_cnt <= 0) {
again:
		if ( (read_cnt = read(fd, read_buf, sizeof(read_buf))) < 0) {
			if (errno == EINTR)
				goto again;
			return(-1);
		} else if (read_cnt == 0)
			return(0);
		read_ptr = read_buf;
	}

	read_cnt--;
	*ptr = *read_ptr++;
	return(1);
}

ssize_t
readline(int fd, void *vptr, size_t maxlen)
{
	ssize_t	n, rc;
	char	c, *ptr;

	ptr = vptr;
	for (n = 1; n < maxlen; n++) {
		if ( (rc = my_read(fd, &c)) == 1) {
			*ptr++ = c;
			if (c == '\n')
				break;	/* newline is stored, like fgets() */
		} else if (rc == 0) {
			*ptr = 0;
			return(n - 1);	/* EOF, n - 1 bytes were read */
		} else
			return(-1);		/* error, errno set by read() */
	}

	*ptr = 0;	/* null terminate like fgets() */
	return(n);
}

ssize_t
Readline(int fd, void *ptr, size_t maxlen)
{
        ssize_t         n;

        if ( (n = readline(fd, ptr, maxlen)) < 0)
                err_sys("readline error");
        return(n);
}



ssize_t						/* Write "n" bytes to a descriptor. */
writen(int fd, const void *vptr, size_t n)
{
	size_t		nleft;
	ssize_t		nwritten;
	const char	*ptr;

	ptr = vptr;
	nleft = n;
	while (nleft > 0) {
		if ( (nwritten = write(fd, ptr, nleft)) <= 0) {
			if (nwritten < 0 && errno == EINTR)
				nwritten = 0;		/* and call write() again */
			else
				return(-1);			/* error */
		}

		nleft -= nwritten;
		ptr   += nwritten;
	}
	return(n);
}


void
Writen(int fd, void *ptr, size_t nbytes)
{
        if (writen(fd, ptr, nbytes) != nbytes)
                err_sys("writen error");
}



void
str_cli(FILE *fp, int sockfd)
{
	char	sendline[MAXLINE], recvline[MAXLINE];

	while (fgets(sendline, MAXLINE, fp) != NULL) {

		Writen(sockfd, sendline, strlen(sendline));

		if (Readline(sockfd, recvline, MAXLINE) == 0)
			err_sys("str_cli: server terminated prematurely");

		fputs(recvline, stdout);
	}
}


void
str_echo(int sockfd)
{
	long		arg1, arg2;
	ssize_t		n;
	char		line[MAXLINE];

	for ( ; ; ) {
		if ( (n = Readline(sockfd, line, MAXLINE)) == 0)
			return;		/* connection closed by other end */
		Writen(sockfd, line, n);
	}
}




int Socket(int family, int type, int protocol)
{
	int n;

	if ((n = socket(family, type, protocol)) < 0)
		err_sys("socket error");

	return n;

}

int Bind(int sockfd, const struct sockaddr *myaddr, socklen_t addrlen)
{
	int n;
	
	if ((n = bind(sockfd, myaddr, addrlen)) < 0)
		err_sys("bind error");
	return n;

}


int Listen(int sockfd, int backlog)
{
	int n;
	char *ptr;
	
	/*can override argument with environment variable*/
	if ((ptr = getenv("LISTENQ")) != NULL)
		backlog = atoi(ptr);

	if ((n = listen(sockfd, backlog)) < 0)
		err_sys("listen error");
	return n;


}

int Accept(int sockfd, struct sockaddr *cliaddr, socklen_t *addrlen)
{
	int n;
	if ((n = accept(sockfd, cliaddr, addrlen)) < 0)
		err_sys("accept error");
	return n;

}

int Connect(int sockfd, const struct sockaddr *servaddr, socklen_t addrlen)
{

	int n;
	if ((n = connect(sockfd, servaddr, addrlen)) < 0)
		err_sys("connect error");

	printf("connect() n:%d\n",n);
	return n;

}







/*add define for Host_serv()*/
struct addrinfo *
host_serv(const char *host, const char *serv, int family, int socktype)
{
	int				n;
	struct addrinfo	hints, *res;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_CANONNAME;	/* always return canonical name */
	hints.ai_family = family;		/* AF_UNSPEC, AF_INET, AF_INET6, etc. */
	hints.ai_socktype = socktype;	/* 0, SOCK_STREAM, SOCK_DGRAM, etc. */

	if ( (n = getaddrinfo(host, serv, &hints, &res)) != 0)
		return(NULL);

	return(res);	/* return pointer to first on linked list */
}
/* end host_serv */

/*
 * There is no easy way to pass back the integer return code from
 * getaddrinfo() in the function above, short of adding another argument
 * that is a pointer, so the easiest way to provide the wrapper function
 * is just to duplicate the simple function as we do here.
 */

struct addrinfo *
Host_serv(const char *host, const char *serv, int family, int socktype)
{
	int				n;
	struct addrinfo	hints, *res;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_CANONNAME;	/* always return canonical name */
	hints.ai_family = family;		/* 0, AF_INET, AF_INET6, etc. */
	hints.ai_socktype = socktype;	/* 0, SOCK_STREAM, SOCK_DGRAM, etc. */

	if ( (n = getaddrinfo(host, serv, &hints, &res)) != 0)
	/*	err_quit("host_serv error for %s, %s: %s",
				 (host == NULL) ? "(no hostname)" : host,
				 (serv == NULL) ? "(no service name)" : serv,
				 gai_strerror(n));
	*/
		err_sys("host_serv error");
	return(res);	/* return pointer to first on linked list */
}
