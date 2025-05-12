#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

// Define a simplified packet event structure
struct packet_event {
    __u64 ts; // Timestamp
    __u32 len; // Packet length
    __u8 data[64]; // Packet data (first 64 bytes)
};

// Define a perf event map for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 128);
} events SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    const void *data_end = (void *) (long) ctx->data_end;
    const void *data = (void *) (long) ctx->data;

    // Basic bounds check for packet data
    if (data >= data_end) {
        return XDP_PASS; // Malformed packet, just pass it
    }

    // Calculate available packet size (safely)
    const __u64 pkt_size = data_end - data;

    // Create event with packet data
    struct packet_event event = {0};
    event.ts = bpf_ktime_get_ns();
    event.len = pkt_size;

    // Safely copy packet data to our event structure (up to 64 bytes)
    const __u32 copy_len = pkt_size > 64 ? 64 : pkt_size;

    // Use bpf_probe_read_kernel to safely copy data from packet memory
    bpf_probe_read_kernel(event.data, copy_len, data);

    // Send event to userspace
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));

    // Just pass the packet along - we're only capturing, not modifying
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
