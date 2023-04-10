#include <sys/types.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define __USE_GNU
#include <dlfcn.h>

typedef unsigned int socklen_t;
typedef struct msghdr msghdr;
typedef struct timeval timeval;
typedef struct sockaddr sockaddr;

typedef ssize_t (*real_read_t)(int, void*, size_t);
typedef ssize_t (*real_write_t)(int, const void*, size_t);
typedef ssize_t (*real_send_t)(int, const void*, size_t, int);
typedef ssize_t (*real_recv_t)(int, void*, size_t, int);
typedef ssize_t (*real_sendmsg_t)(int, const struct msghdr*, int);
typedef ssize_t (*real_recvmsg_t)(int, struct msghdr*, int);
typedef ssize_t (*real_sendto_t)(int, const void*, size_t, int, const struct sockaddr*, socklen_t);
typedef ssize_t (*real_recvfrom_t)(int fd, void* restrict buffer, size_t length, int flags, struct sockaddr* restrict address, socklen_t* restrict address_len);

void rw_overwrite_log_hjk(char* function_name, int fd, ssize_t bytes){
	timeval current;
	gettimeofday(&current, NULL);
	pid_t pid = getpid();
	char process_path[1024] = {0};
	char default_process_path[] = "NOT_FOUND";
	char *process_name = default_process_path;
	if(readlink("/proc/self/exe", process_path, 1024) > 0){
		process_name = strrchr(process_path, '/');
	}
	FILE * fp = fopen("/var/log/socker-watcher-log.txt", "a");
	fprintf(fp, "[Socket Watcher]  second: %ld,  microsecond: %ld, pid:%d, process-name:%s, call: %s, fd:%d, bytes:%ld \n", current.tv_sec, current.tv_usec, pid, process_name, function_name, fd, bytes);
	fclose(fp);
}

timeval rw_overwrite_get_time_hjk(){
	timeval current;
	gettimeofday(&current, NULL);
	return current;
}

// ssize_t read(int fd, void* buf, size_t count) {
// 	timeval time = rw_overwrite_get_time_hjk();
//     ssize_t bytes = ((real_read_t)dlsym(RTLD_NEXT, "read"))(fd, buf, count);
// 	rw_overwrite_log_hjk("read", fd, bytes);
// 	return bytes;
// }

ssize_t readv(int fd, const struct iovec *iov, int iovcnt) {
	timeval time = rw_overwrite_get_time_hjk();
	ssize_t bytes = ((real_read_t)dlsym(RTLD_NEXT, "readv"))(fd, (void*)iov, iovcnt);
	rw_overwrite_log_hjk("readv", fd, bytes);
	return bytes;
}

// ssize_t write(int fd, const void* data, size_t size) {
// 	timeval time = rw_overwrite_get_time_hjk();
// 	ssize_t bytes = ((real_write_t)dlsym(RTLD_NEXT, "write"))(fd, data, size);
// 	rw_overwrite_log_hjk("write", fd, bytes);
// 	return bytes;
// }

ssize_t writev(int fd, const struct iovec *iov, int iovcnt) {
	timeval time = rw_overwrite_get_time_hjk();
	ssize_t bytes = ((real_write_t)dlsym(RTLD_NEXT, "writev"))(fd, iov, iovcnt);
	rw_overwrite_log_hjk("writev", fd, bytes);
	return bytes;
}


ssize_t send(int fd, const void* buffer, size_t length, int flags) {
	timeval time = rw_overwrite_get_time_hjk();
	ssize_t bytes = ((real_send_t)dlsym(RTLD_NEXT, "send"))(fd, buffer, length, flags);
	rw_overwrite_log_hjk("send", fd, bytes);
	return bytes;  
}

ssize_t recv(int fd, void *buffer, size_t length, int flags) {
	timeval time = rw_overwrite_get_time_hjk();
	ssize_t bytes = ((real_recv_t)dlsym(RTLD_NEXT, "recv"))(fd, buffer, length, flags);
	rw_overwrite_log_hjk("recv", fd, bytes);
	return bytes;
}

ssize_t sendto(int fd, const void *buffer, size_t length, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
	timeval time = rw_overwrite_get_time_hjk();
	ssize_t bytes = ((real_sendto_t)dlsym(RTLD_NEXT, "sendto"))(fd, buffer, length, flags, dest_addr, addrlen);
	rw_overwrite_log_hjk("sendto", fd, bytes);
	return bytes;
}

ssize_t recvfrom(int fd, void *buffer, size_t length, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
	timeval time = rw_overwrite_get_time_hjk();
	ssize_t bytes = ((real_recvfrom_t)dlsym(RTLD_NEXT, "recvfrom"))(fd, buffer, length, flags, src_addr, addrlen);
	rw_overwrite_log_hjk("recvfrom", fd, bytes);
	return bytes;
}

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
	timeval time = rw_overwrite_get_time_hjk();
	ssize_t bytes = ((real_sendmsg_t)dlsym(RTLD_NEXT, "sendmsg"))(fd, msg, flags);
	rw_overwrite_log_hjk("sendmsg", fd, bytes);
	return bytes;
}

ssize_t recvmsg(int fd, struct msghdr *msg, int flags) {
	timeval time = rw_overwrite_get_time_hjk();
	ssize_t bytes = ((real_recvmsg_t)dlsym(RTLD_NEXT, "recvmsg"))(fd, msg, flags);
	rw_overwrite_log_hjk("recvmsg", fd, bytes);
	return bytes;
}
