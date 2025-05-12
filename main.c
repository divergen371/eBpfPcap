#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>      /* For syscall() */
#include <sys/syscall.h> /* For __NR_perf_event_open */
#include <sys/ioctl.h>   /* For PERF_EVENT_IOC_* */
#include <linux/perf_event.h> /* For perf_event_attr */
#include <errno.h>       /* For errno and strerror() */
#include <string.h>      /* For strerror() */
#include <net/if.h>  // For if_nametoindex
#include <fcntl.h>   // For access
#include <poll.h>
#include <sys/mman.h>
#include <sys/resource.h> // For setrlimit and RLIMIT_MEMLOCK
#include <sys/sysinfo.h> // For get_nprocs()

// Function prototype for perf_event_open
int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu,
                    int group_fd, unsigned long flags);

struct packet_event {
    unsigned long long ts;
    unsigned int len;
    unsigned char data[64];
};

static volatile int exiting = 0;
void sigint_handler(int signo) { exiting = 1; }

#define MAX_CPUS 128
static int perf_event_fds[MAX_CPUS] = {0};
struct perf_event_mmap_page *headers[MAX_CPUS] = {NULL};

// A large buffer to receive and process events
#define PERF_BUFFER_PAGES 16
#define PERF_BUFFER_SIZE ((1 << 12) * PERF_BUFFER_PAGES)
#define PERF_TAIL_MASK  (PERF_BUFFER_SIZE - 1)

struct perf_event_sample {
    struct perf_event_header header;
    __u32 size;
    char data[];
};

static void handle_event(int cpu, const void *data, __u32 size) {
    const struct packet_event *e = data;
    printf("Packet: len=%u ts=%llu ", e->len, e->ts);
    for (unsigned i = 0; i < (e->len < 64 ? e->len : 64); ++i) {
        printf("%02x ", e->data[i]);
    }
    printf("\n");
}

int bump_memlock_rlimit(void) {
    const struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    int ret = setrlimit(RLIMIT_MEMLOCK, &r);
    if (ret) {
        fprintf(stderr, "Error setting RLIMIT_MEMLOCK: %s\n", strerror(errno));
        fprintf(stderr, "Try running with sudo or as root\n");
    }
    return ret;
}

static void setup_perf_event(int map_fd, int cpu) {
    struct perf_event_attr attr = {
        .sample_type = PERF_SAMPLE_RAW,
        .type = PERF_TYPE_SOFTWARE,
        .config = PERF_COUNT_SW_BPF_OUTPUT,
        .wakeup_events = 1,
    };

    int pfd = perf_event_open(&attr, -1, cpu, -1, 0);
    if (pfd < 0) {
        fprintf(stderr, "Failed to open perf event on CPU %d: %s\n", cpu,
                strerror(errno));
        return;
    }

    // Set up the mmap area for this CPU
    void *base = mmap(
        NULL, PERF_BUFFER_SIZE + sizeof(struct perf_event_mmap_page),
        PROT_READ | PROT_WRITE, MAP_SHARED, pfd, 0);
    if (base == MAP_FAILED) {
        close(pfd);
        fprintf(stderr, "Failed to mmap perf event for CPU %d: %s\n", cpu,
                strerror(errno));
        return;
    }

    headers[cpu] = base;
    perf_event_fds[cpu] = pfd;

    // Update the BPF map with this perf event FD
    int key = cpu;
    if (bpf_map_update_elem(map_fd, &key, &pfd, BPF_ANY) < 0) {
        fprintf(stderr, "Failed to update BPF map for CPU %d: %s\n", cpu,
                strerror(errno));
    }
}

static void poll_events(void) {
    struct pollfd fds[MAX_CPUS];
    int nfds = 0;

    // Set up poll structure
    for (int i = 0; i < MAX_CPUS; i++) {
        if (perf_event_fds[i] > 0) {
            fds[nfds].fd = perf_event_fds[i];
            fds[nfds].events = POLLIN;
            nfds++;
        }
    }

    if (poll(fds, nfds, 100) <= 0)
        return; // Timeout or error

    // Process all available events
    for (int i = 0; i < nfds; i++) {
        if (fds[i].revents & POLLIN) {
            int cpu = -1;
            // Find which CPU this FD belongs to
            for (int j = 0; j < MAX_CPUS; j++) {
                if (perf_event_fds[j] == fds[i].fd) {
                    cpu = j;
                    break;
                }
            }

            if (cpu == -1)
                continue;

            // Process events for this CPU
            struct perf_event_mmap_page *header = headers[cpu];
            if (!header)
                continue;

            __u64 tail = header->data_tail;
            __u64 head = header->data_head;

            // Ensure we see the most up-to-date head
            asm volatile("" ::: "memory");

            void *base = ((void *) header) + header->data_offset;

            while (tail < head) {
                struct perf_event_sample *sample =
                        base + (tail & PERF_TAIL_MASK);
                if (sample->header.type == PERF_RECORD_SAMPLE) {
                    handle_event(cpu, sample->data, sample->size);
                }
                tail += sample->header.size;
            }

            // Update the data_tail
            header->data_tail = head;
        }
    }
}

// Function to open a perf event
int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu,
                    int group_fd, unsigned long flags) {
#ifndef __NR_perf_event_open
#if defined(__x86_64__)
#define __NR_perf_event_open 298
#elif defined(__i386__)
#define __NR_perf_event_open 336
#elif defined(__aarch64__)
#define __NR_perf_event_open 241
#elif defined(__arm__)
#define __NR_perf_event_open 364
#else
#error "Unsupported architecture for __NR_perf_event_open"
#endif
#endif
    return syscall((long) __NR_perf_event_open, attr, pid, cpu, group_fd,
                   flags);
}

int main(int argc, char **argv) {
    struct bpf_object *obj = NULL;
    int ifindex = 0;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    // Get interface index from name
    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        fprintf(stderr, "Invalid interface name: %s\n", argv[1]);
        return 1;
    }

    // Check if running as root
    if (geteuid() != 0) {
        fprintf(
            stderr,
            "This program requires root privileges to load eBPF programs.\n");
        fprintf(stderr, "Please run with sudo or as root.\n");
        return 1;
    }

    signal(SIGINT, sigint_handler);

    // Increase the RLIMIT_MEMLOCK limit
    if (bump_memlock_rlimit()) {
        fprintf(
            stderr,
            "Failed to increase RLIMIT_MEMLOCK limit. Continuing anyway, but loading may fail.\n");
    }

    // Load BPF program
    char prog_path[256];
    // Check if file exists in the current directory
    if (access("xdp_prog_kern.o", F_OK) != -1) {
        snprintf(prog_path, sizeof(prog_path), "xdp_prog_kern.o");
    } else {
        // Try to find the file in the build directory
        const char *build_dirs[] = {
            ".", "build", "cmake-build-debug", "../build",
            "../cmake-build-debug"
        };
        int found = 0;
        for (int i = 0; i < sizeof(build_dirs) / sizeof(build_dirs[0]); i++) {
            snprintf(prog_path, sizeof(prog_path), "%s/xdp_prog_kern.o",
                     build_dirs[i]);
            if (access(prog_path, F_OK) != -1) {
                found = 1;
                break;
            }
        }
        if (!found) {
            fprintf(stderr, "Could not find xdp_prog_kern.o\n");
            return 1;
        }
    }

    printf("Loading BPF program from: %s\n", prog_path);

    // Open BPF object file
    obj = bpf_object__open(prog_path);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    // Find program by name
    struct bpf_program *prog =
            bpf_object__find_program_by_name(obj, "xdp_prog");
    if (!prog) {
        fprintf(stderr, "Failed to find XDP program in object\n");
        bpf_object__close(obj);
        return 1;
    }

    // Load BPF object
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        bpf_object__close(obj);
        return 1;
    }

    // Get file descriptors for program and map
    int prog_fd = bpf_program__fd(prog);
    int map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (prog_fd < 0 || map_fd < 0) {
        fprintf(
            stderr, "Failed to get BPF program or map: prog_fd=%d, map_fd=%d\n",
            prog_fd, map_fd);
        bpf_object__close(obj);
        return 1;
    }

    // Set up perf events for online CPUs
    const unsigned int ncpus = get_nprocs();
    for (unsigned int i = 0; i < ncpus; i++) {
        setup_perf_event(map_fd, i);
    }

    // Attach XDP program to interface
    const int err = bpf_xdp_attach(ifindex, prog_fd, 0, NULL);
    if (err < 0) {
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    printf("Capturing packets on interface %s. Press Ctrl+C to exit.\n",
           argv[1]);

    // Main loop
    while (!exiting) {
        poll_events();
    }

    // Clean up
    bpf_xdp_detach(ifindex, 0, NULL);

    for (int i = 0; i < MAX_CPUS; i++) {
        if (headers[i]) {
            munmap(headers[i],
                   PERF_BUFFER_SIZE + sizeof(struct perf_event_mmap_page));
            close(perf_event_fds[i]);
        }
    }

    bpf_object__close(obj);
    return 0;
}
