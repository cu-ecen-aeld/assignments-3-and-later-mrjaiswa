#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "aesd_ioctl.h"

#ifdef USE_AESD_CHAR_DEVICE
#define PATH "/dev/aesdchar"
#else
#define PATH "/var/tmp/aesdsocketdata"
#endif
#define PORT "9000"
#define BACKLOG 5
#define INITIAL_BUFFER_CAPACITY 8192

struct client_data {
  char addr_str[INET6_ADDRSTRLEN];
  int sock;
  bool done;
};

struct client_entry {
  pthread_t tid;
  struct client_data *data;
  SLIST_ENTRY(client_entry) entries;
};

static bool g_running = false;

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

// Timestamp thread
static void timestamp_thread(union sigval unused) {
  int fd;
  time_t ts;
  struct tm *tm;
  char str[256];

  ts = time(NULL);
  tm = localtime(&ts);
  if (tm == NULL) {
    perror("localtime");
    return;
  }

  // RFC 2822 compliant format: "%a, %d %b %Y %T %z"
  const char *fmt = "timestamp: %a, %d %b %Y %T %z\n";
  if (strftime(str, sizeof(str), fmt, tm) == 0) {
    fprintf(stderr, "strftime");
    return;
  }

  fd = open(PATH, O_RDWR | O_CREAT | O_APPEND, 0644);
  if (fd == -1) {
    perror("open");
    return;
  }

  const int ret = pthread_mutex_lock(&g_mutex);
  if (ret != 0) {
    fprintf(stderr, "lock: %d", ret);
    return;
  }

  if (lseek(fd, 0, SEEK_END) == -1) {
    perror("lseek");
    goto timestamp_error_unlock;
  }

  if (write(fd, str, strnlen(str, sizeof(str))) == -1) {
    perror("write");
  }

timestamp_error_unlock:
  pthread_mutex_unlock(&g_mutex);
  close(fd);
}

// Start timestamp timer
static int start_timer(timer_t *timer) {
  struct sigevent evp;
  int ret;

  evp.sigev_value.sival_ptr = timer;
  evp.sigev_notify = SIGEV_THREAD;
  evp.sigev_notify_function = timestamp_thread;
  evp.sigev_notify_attributes = NULL;
  ret = timer_create(CLOCK_MONOTONIC, &evp, timer);
  if (ret != 0) {
    ret = errno;
    return ret;
  }

#ifndef USE_AESD_CHAR_DEVICE
  struct itimerspec ts;
  ts.it_interval.tv_sec = 10;
  ts.it_interval.tv_nsec = 0;
  ts.it_value.tv_sec = 10;
  ts.it_value.tv_nsec = 0;
  ret = timer_settime(*timer, 0, &ts, NULL);
  if (ret != 0) {
    ret = errno;
    timer_delete(*timer);
    return ret;
  }
#endif

  return 0;
}

// Client thread
static void *client_thread(void *thread_data) {
  struct client_data *data = (struct client_data *)thread_data;
  int res;
  int fd;
  char *buf;
  size_t buf_index = 0;
  size_t buf_capacity = INITIAL_BUFFER_CAPACITY;
  ssize_t received;
  struct aesd_seekto seekto;
  intptr_t status = 0;

  buf = malloc(buf_capacity);
  if (buf == NULL) {
    status = errno;
    perror("malloc");
    return (void *)status;
  }

  fd = open(PATH, O_RDWR | O_CREAT | O_APPEND, 0644);
  if (fd == -1) {
    status = errno;
    perror("open");
    free(buf);
    return (void *)status;
  }

  for (bool delimiter = false; !delimiter;) {
    received = recv(data->sock, &buf[buf_index], buf_capacity - buf_index, 0);
    if (received == -1) {
      if (errno != EINTR) {
        perror("recv");
      }
      status = errno;
      break;
    }
    if (received == 0) {
      break;
    }

    const size_t buffer_end = buf_index + received;
    for (size_t i = buf_index; i < buffer_end; i++) {
      buf_index++;
      // Any data after newline delimiter is discarded
      if (buf[i] == '\n') {
        delimiter = true;
        break;
      }
    }

    if (!delimiter) {
      // Double buffer capacity when current capacity reached
      if (buf_index == buf_capacity) {
        buf = realloc(buf, 2 * buf_capacity);
        if (buf == NULL) {
          status = errno;
          perror("realloc");
          break;
        }
        buf_capacity *= 2;
      }
      // Continue receiving until delimiter
      continue;
    }

    status = pthread_mutex_lock(&g_mutex);
    if (status != 0) {
      fprintf(stderr, "lock: %d", (int)status);
      break;
    }

#ifndef USE_AESD_CHAR_DEVICE
    // Append received line to end of file
    if (lseek(fd, 0, SEEK_END) == -1) {
      status = errno;
      perror("lseek");
      goto client_error_unlock;
    }
#else
    buf[buf_index] = '\0';
    res = sscanf(buf, "AESDCHAR_IOCSEEKTO:%u,%u", &seekto.write_cmd,
                 &seekto.write_cmd_offset);
    if (res == 2) {
      // printf("Command %u with offset %u\n", seekto.write_cmd, seekto.write_cmd_offset);
      if (ioctl(fd, AESDCHAR_IOCSEEKTO, &seekto) != 0) {
        status = errno;
        perror("ioctl");
        goto client_error_unlock;
      }
    } else
#endif
    if (write(fd, buf, buf_index) == -1) {
      status = errno;
      perror("write");
      goto client_error_unlock;
    }

    buf_index = 0;

#ifndef USE_AESD_CHAR_DEVICE
    // Send entire file contents to client
    if (lseek(fd, 0, SEEK_SET) == -1) {
      status = errno;
      perror("lseek");
      goto client_error_unlock;
    }
#endif

    do {
      received = read(fd, buf, buf_capacity);
      if (received == -1) {
        status = errno;
        perror("read");
        goto client_error_unlock;
      }
      if (send(data->sock, buf, received, 0) == -1) {
        status = errno;
        perror("send");
        goto client_error_unlock;
      }
    } while (received != 0);

    pthread_mutex_unlock(&g_mutex);
    continue;

  client_error_unlock:
    pthread_mutex_unlock(&g_mutex);
    break;
  }

  syslog(LOG_INFO, "Closing connection from %s", data->addr_str);
  printf("Closing connection from %s\n", data->addr_str);

  close(fd);

  free(buf);

  close(data->sock);

  return (void *)status;
}

// Create server socket
static int create_socket(void) {
  int sock;
  int status;
  struct addrinfo *info;
  struct addrinfo *info_list;

  struct addrinfo hints = {0};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  if ((status = getaddrinfo(NULL, PORT, &hints, &info_list)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
    return -EADDRNOTAVAIL;
  }

  for (info = info_list; info != NULL; info = info->ai_next) {
    sock = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
    if (sock == -1) {
      status = errno;
      continue;
    }

    int option = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    if (bind(sock, info->ai_addr, info->ai_addrlen) == 0) {
      break;
    }

    status = errno;

    close(sock);
  }

  freeaddrinfo(info_list);

  if (info == NULL) {
    return -status;
  }

  return sock;
}

// Call only async-signal-safe functions in signal handler
static void signal_handler(int signo) {
  if (signo == SIGINT || signo == SIGTERM) {
    g_running = false;
    const char *msg = "Caught signal, exiting\n";
    write(STDOUT_FILENO, msg, strnlen(msg, 24));
  } else {
    const char *msg = "Unexpected signal\n";
    write(STDERR_FILENO, msg, strnlen(msg, 19));
  }
}

static inline void *get_sin_addr(struct sockaddr *sa) {
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in *)sa)->sin_addr);
  }

  return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

int main(int argc, char *argv[]) {
  int opt;
  bool daemon = false;
  int sock;
  int peer_sock;
  struct sockaddr_storage peer_addr;
  socklen_t peer_addr_size;
  SLIST_HEAD(slist_head, client_entry) head = SLIST_HEAD_INITIALIZER(head);
  timer_t timer;
  int status = 0;

  while ((opt = getopt(argc, argv, "d")) != -1) {
    switch (opt) {
      case 'd':
        daemon = true;
        break;
      case '?':
        return -1;
    }
  }

  SLIST_INIT(&head);

  // Traditional forking UNIX daemon
  if (daemon) {
    const pid_t pid = fork();

    if (pid != 0) {
      exit(0);
    }

    if (pid == -1) {
      perror("fork");
      return -1;
    }

    if (setsid() == -1) {
      perror("setsid");
      return -1;
    }

    if (chdir("/") == -1) {
      perror("chdir");
      return -1;
    }

    // Close and redirect stdin, stderr, and stdlog
    for (int fd = 0; fd < 3; fd++) {
      close(fd);
    }

    open("/dev/null", O_RDWR);
    dup(0);
    dup(0);
  }

  openlog(NULL, 0, LOG_USER);

  sock = create_socket();
  if (sock < 0) {
    fprintf(stderr, "Could not bind: %s\n", strerror(-sock));
    return -1;
  }

  g_running = true;

  {
    struct sigaction act = {0};
    act.sa_handler = signal_handler;

    if (sigaction(SIGINT, &act, NULL) == -1) {
      perror("sigaction");
      return -1;
    }

    if (sigaction(SIGTERM, &act, NULL) == -1) {
      perror("sigaction");
      return -1;
    }
  }

  status = start_timer(&timer);
  if (status != 0) {
    fprintf(stderr, "create_timer: %s\n", strerror(status));
    // TODO Better cleanup
    close(sock);
    return -1;
  }

  status = listen(sock, BACKLOG);
  if (status == -1) {
    perror("listen");
    // TODO Better Cleanup
    close(sock);
    timer_delete(timer);
    return -1;
  }

  while (g_running) {
    peer_addr_size = sizeof peer_addr;
    peer_sock = accept(sock, (struct sockaddr *)&peer_addr, &peer_addr_size);
    if (peer_sock == -1) {
      if (errno != EINTR) {
        status = -1;
      }
      break;
    }

    struct client_data *data = calloc(1, sizeof(struct client_data));
    if (data == NULL) {
      perror("calloc");
      status = -1;
      break;
    }

    inet_ntop(peer_addr.ss_family, get_sin_addr((struct sockaddr *)&peer_addr),
              data->addr_str, sizeof data->addr_str);

    syslog(LOG_INFO, "Accepted connection from %s", data->addr_str);
    printf("Accepted connection from %s\n", data->addr_str);

    data->sock = peer_sock;

    struct client_entry *entry = NULL;

    // Join any finished threads
    SLIST_FOREACH(entry, &head, entries) {
      if (entry->data == NULL) {
        continue;
      }
      if (!entry->data->done) {
        continue;
      }

      const int rc = pthread_join(entry->tid, NULL);
      if (rc != 0) {
        fprintf(stderr, "join: %s", strerror(rc));
        // FIXME Maybe fail fast here instead
        entry->data->done = false;
      } else {
        free(entry->data);
        entry->data = NULL;
      }
    }

    // Try to find an empty entry
    SLIST_FOREACH(entry, &head, entries) {
      if (entry->data == NULL) {
        break;
      }
    }

    // Insert if empty entry not found
    if (entry == NULL) {
      entry = calloc(1, sizeof(struct client_entry));
      if (entry == NULL) {
        perror("calloc");
        free(data);
        status = -1;
        break;
      }
      SLIST_INSERT_HEAD(&head, entry, entries);
    }

    const int rc =
        pthread_create(&entry->tid, NULL, client_thread, (void *)data);
    if (rc != 0) {
      fprintf(stderr, "create: %s", strerror(rc));
      status = -1;
      break;
    }

    entry->data = data;
  }

  if (!g_running) {
    syslog(LOG_INFO, "Caught signal, exiting");
  } else {
    g_running = false;
  }

  close(sock);

  timer_delete(timer);

  // File still exists until all descriptors are closed
#ifndef USE_AESD_CHAR_DEVICE
  unlink(PATH);
#endif

  // Join threads
  struct client_entry *entry;
  SLIST_FOREACH(entry, &head, entries) {
    if (entry->data == NULL) {
      continue;
    }
    pthread_join(entry->tid, NULL);
    free(entry->data);
    entry->data = NULL;
  }

  while (!SLIST_EMPTY(&head)) {
    entry = SLIST_FIRST(&head);
    SLIST_REMOVE_HEAD(&head, entries);
    free(entry);
  }

  return status;
}
