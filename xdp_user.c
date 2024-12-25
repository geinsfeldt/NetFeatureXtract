#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <time.h>
#include "uthash.h"

#include "xdp_common.h"

#define MAX_ENTRIES 1024
#define FLOW_MAP_PATH "/sys/fs/bpf/flow_map"
#define FEATURE_CONFIG_MAP_PATH "/sys/fs/bpf/features_config"
#define INACTIVE_THRESHOLD 300000000000
#define FEATURE_MASK 0b00000000000000000000000000111111
#define FEATURE_PRECISION 1000

static void map_delete() 
{
	// Delete old maps
    if (unlink(FLOW_MAP_PATH) == 0) {
		printf("Flow map unpinned and deleted.\n");
    }
    if (unlink(FEATURE_CONFIG_MAP_PATH) == 0) {
    printf("Config map unpinned and deleted.\n");
    }

}

__u64 get_current_time_ns() {
    // Get current time in nanoseconds
    struct timespec ts;
    clock_gettime(1, &ts);
    return ((__u64)ts.tv_sec * 1000000000ULL) + ts.tv_nsec;
}

void print_flow_stats(struct flow_key *key, struct flow_stats *stats) {
    
    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
    
    if (key->ip_version == 4) {
        inet_ntop(AF_INET, &key->src_ip.v4, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &key->dst_ip.v4, dst_ip, INET_ADDRSTRLEN);
    } else {
        inet_ntop(AF_INET6, &key->src_ip.v6, src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &key->dst_ip.v6, dst_ip, INET6_ADDRSTRLEN);
    }

    printf("Flow: %s:%d -> %s:%d (IPv%d, Proto: %d)\n", 
            src_ip, ntohs(key->src_port), dst_ip, ntohs(key->dst_port),
            key->ip_version, key->protocol);
    printf("  Packets: %llu\n", stats->packets);
    printf("  Bytes: %llu\n", stats->bytes);
    printf("  Duration: %.3f seconds\n", (double) stats->duration / FEATURE_PRECISION);
    printf("  Packets per second: %.3f\n", (double) stats->pps / FEATURE_PRECISION);
    printf("  Bytes per second: %.3f\n", (double) stats->bps / FEATURE_PRECISION);
    printf("  Max packet length: %u\n", stats->max_pkt_len);
    printf("  Min packet length: %u\n", stats->min_pkt_len);
    printf("  Max packet per second: %.3f\n", (double) stats->max_pps / FEATURE_PRECISION);
    printf("  Min packet per second: %.3f\n", (double) stats->min_pps / FEATURE_PRECISION);
    printf("  Max bytes per second: %.3f\n", (double) stats->max_bps / FEATURE_PRECISION);
    printf("  Min bytes per second: %.3f\n", (double) stats->min_bps / FEATURE_PRECISION);
    printf("  Average packet per second: %.3f\n", (double) stats->avg_pps / FEATURE_PRECISION);
    printf("  Average bytes per second: %.3f\n", (double) stats->avg_bps / FEATURE_PRECISION);
    printf("  Average number of bytes: %.3f\n", (double) stats->avg_bpp / FEATURE_PRECISION);

    printf("\n");
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    int map_fd;
    int map_features_fd;
    __u32 key = 0;
    __u32 feature_mask = FEATURE_MASK;
	char *dev_name = argv[1];
    int err;
	int ifindex;
	int prog_fd;

    // Load BPF ELF object file
    obj = bpf_object__open("xdp_kern_feature_extract.o");
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

	// Clean existing maps
	map_delete();

	// Load BPF program in kernel
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

	// Search XDP coded inside of BPF object program
	struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_flow_stats");
	if (!prog) {
		fprintf(stderr, "Error finding BPF program in object\n");
		bpf_object__close(obj);
		return 1;
	}

	// Get file descriptor of XDP program
	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		fprintf(stderr, "Error getting file descriptor for BPF program\n");
		bpf_object__close(obj);
		return 1;
	}

    // Get informed interface
	ifindex = if_nametoindex(dev_name);
	if (!ifindex) {
		fprintf(stderr, "ERROR: unknown interface %s\n", dev_name);
		return 1;
	}
	
    // Conect XDP program to interface
	err = bpf_xdp_attach(ifindex, prog_fd, 0, NULL);
	if (err) {
		fprintf(stderr, "ERROR: attaching XDP program to interface failed\n");
		return 1;
	}

    // Get file descriptor of features_config map
    map_features_fd = bpf_object__find_map_fd_by_name(obj, "features_config");
    if (map_features_fd < 0) {
        fprintf(stderr, "ERROR: finding features_config in obj file failed\n");
        return 1;
    }

    // Define the features to extract and their precision
    struct features_config default_config = {
        .features = FEATURE_MASK,
        .precision = FEATURE_PRECISION,
        .timeout = INACTIVE_THRESHOLD,
    };

    // Update the feature configuration map with given config
    if (bpf_map_update_elem(map_features_fd, &key, &default_config, BPF_ANY)) {
        fprintf(stderr, "ERROR: updating features_config in obj file failed\n");
        return 1;
    }

    // Get file descriptor of flow_map
    map_fd = bpf_object__find_map_fd_by_name(obj, "flow_map");
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: finding flow_map in obj file failed\n");
        return 1;
    }

    printf("Map FD: %d\n", map_fd);

    // Loop principal
    while (1) {
        struct flow_key keys[MAX_ENTRIES];
        struct flow_stats values[MAX_ENTRIES];
        __u32 key_size = sizeof(struct flow_key);
        __u32 value_size = sizeof(struct flow_stats);
        __u32 num_entries = MAX_ENTRIES;
        void *prev_key = NULL;
        int err;

        // Check if flow map exists
        err = bpf_map_get_next_key(map_fd, prev_key, &keys[0]);
        if (err) {
            if (errno == ENOENT) {
                printf("Map is empty\n");
            } else {
                fprintf(stderr, "Error getting first key: %d (%s)\n", err, strerror(errno));
            }
            sleep(1);
            continue;
        }

        // For each identified flow
        for (int i = 0; i < MAX_ENTRIES; i++) {

            // Search for data in flow map
            err = bpf_map_lookup_elem(map_fd, &keys[i], &values[i]);
            if (err) {
                if (errno == ENOENT) {
                    break;  // No more entries
                } else {
                    fprintf(stderr, "Error looking up element %d: %d (%s)\n", i, err, strerror(errno));
                    break;
                }
            }

            // Print flow data
            print_flow_stats(&keys[i], &values[i]);

            prev_key = &keys[i];

            // Check if next flow exists
            err = bpf_map_get_next_key(map_fd, prev_key, &keys[i+1]);
            if (err) {
                if (errno == ENOENT) {
                    break;  // No more entries
                } else {
                    fprintf(stderr, "Error getting next key: %d (%s)\n", err, strerror(errno));
                    break;
                }
            }
        }

        sleep(1);  // Update each second
    }

    return 0;
}
