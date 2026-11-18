// KNSH-077 C3: deterministic test tree for the shadow-cloning timings (NFR-PERF-06).
//
// usage: gentree <dest> [files=100000] [seed=77]
//
// Shape (documented so the run is reproducible; the same seed gives the same tree):
//   - directories: a complete tree of fan-out 5 down to depth 5 below <dest> (1 + 5 + ... + 3125 = 3906
//     directories, depth 0..5), named d0..d4;
//   - files: <files> regular files spread over every directory, 1..50 per directory drawn uniformly, the
//     last directories topped up or trimmed so the total is exact; names f<n>.<ext> with a mix of
//     source-like extensions;
//   - sizes, drawn per file (log-uniform inside each bucket):
//       2.0%  0 B
//      30.0%  1 B - 1 KiB
//      42.8%  1 KiB - 8 KiB
//      20.0%  8 KiB - 64 KiB
//       5.0%  64 KiB - 1 MiB
//       0.2%  1 MiB - 4 MiB
//   - content: pseudo-random bytes (xorshift64*), so nothing is sparse or compressible.
//
// Prints one summary line per fact (count, bytes, histogram, depth) for the results file.

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FANOUT 5
#define MAXDEPTH 5

static uint64_t rng_state;

static uint64_t rng(void) {
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return rng_state * 2685821657736338717ULL;
}

static double unit(void) { return (double)(rng() >> 11) / (double)(1ULL << 53); }

static uint64_t log_uniform(uint64_t lo, uint64_t hi) {
    double v = exp(log((double)lo) + unit() * (log((double)hi) - log((double)lo)));
    return (uint64_t)v;
}

struct bucket {
    double share;
    uint64_t lo, hi;
    const char *name;
};

static const struct bucket BUCKETS[] = {
    {0.020, 0, 0, "0B"},
    {0.300, 1, 1024, "1B-1KiB"},
    {0.428, 1024, 8192, "1-8KiB"},
    {0.200, 8192, 65536, "8-64KiB"},
    {0.050, 65536, 1048576, "64KiB-1MiB"},
    {0.002, 1048576, 4194304, "1-4MiB"},
};
#define NBUCKETS (sizeof BUCKETS / sizeof BUCKETS[0])

static const char *EXTS[] = {"rs", "ts", "js", "json", "md", "c", "h", "py", "txt", "lock", "toml", "png"};

static uint64_t hist_n[NBUCKETS], hist_bytes[NBUCKETS];
static uint64_t total_bytes;
static char buf[4194304];

static void fill(size_t n) {
    for (size_t i = 0; i + 8 <= n; i += 8) {
        uint64_t v = rng();
        memcpy(buf + i, &v, 8);
    }
}

static void write_file(const char *path, uint64_t size) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) {
        fprintf(stderr, "gentree: open %s: %s\n", path, strerror(errno));
        exit(1);
    }
    fill((size_t)size + 8);
    size_t off = 0;
    while (off < size) {
        ssize_t w = write(fd, buf + off, (size_t)size - off);
        if (w <= 0) {
            fprintf(stderr, "gentree: write %s: %s\n", path, strerror(errno));
            exit(1);
        }
        off += (size_t)w;
    }
    close(fd);
}

static void one_file(const char *dir, long n) {
    double u = unit(), acc = 0;
    size_t b = NBUCKETS - 1;
    for (size_t i = 0; i < NBUCKETS; i++) {
        acc += BUCKETS[i].share;
        if (u < acc) {
            b = i;
            break;
        }
    }
    uint64_t size = BUCKETS[b].hi == 0 ? 0 : log_uniform(BUCKETS[b].lo, BUCKETS[b].hi);
    char path[1024];
    snprintf(path, sizeof path, "%s/f%ld.%s", dir, n, EXTS[rng() % (sizeof EXTS / sizeof EXTS[0])]);
    write_file(path, size);
    hist_n[b]++;
    hist_bytes[b] += size;
    total_bytes += size;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: gentree <dest> [files] [seed]\n");
        return 2;
    }
    const char *dest = argv[1];
    long files = argc > 2 ? atol(argv[2]) : 100000;
    rng_state = (argc > 3 ? strtoull(argv[3], NULL, 10) : 77) * 0x9E3779B97F4A7C15ULL | 1;

    // Directories in breadth-first order: index i has children 5i+1 .. 5i+5 while depth < MAXDEPTH.
    long ndirs = 0, level = 1;
    for (int d = 0; d <= MAXDEPTH; d++, level *= FANOUT) ndirs += level;
    char **dirs = calloc((size_t)ndirs, sizeof *dirs);
    if (mkdir(dest, 0755) != 0) {
        fprintf(stderr, "gentree: mkdir %s: %s\n", dest, strerror(errno));
        return 1;
    }
    dirs[0] = strdup(dest);
    for (long i = 0; i < ndirs; i++) {
        for (int c = 0; c < FANOUT; c++) {
            long child = FANOUT * i + c + 1;
            if (child >= ndirs) break;
            char path[1024];
            snprintf(path, sizeof path, "%s/d%d", dirs[i], c);
            if (mkdir(path, 0755) != 0) {
                fprintf(stderr, "gentree: mkdir %s: %s\n", path, strerror(errno));
                return 1;
            }
            dirs[child] = strdup(path);
        }
    }

    // Per-directory counts, then correct the total from the end so it is exact.
    long *count = calloc((size_t)ndirs, sizeof *count), sum = 0;
    for (long i = 0; i < ndirs; i++) sum += (count[i] = 1 + (long)(rng() % 50));
    for (long i = ndirs - 1; sum != files; i = (i == 0 ? ndirs - 1 : i - 1)) {
        if (sum < files) {
            count[i]++;
            sum++;
        } else if (count[i] > 0) {
            count[i]--;
            sum--;
        }
    }
    long n = 0;
    for (long i = 0; i < ndirs; i++)
        for (long k = 0; k < count[i]; k++) one_file(dirs[i], n++);

    printf("files\t%ld\n", n);
    printf("directories\t%ld (fan-out %d, depth 0..%d)\n", ndirs, FANOUT, MAXDEPTH);
    printf("bytes\t%llu (%.2f GiB)\n", (unsigned long long)total_bytes, (double)total_bytes / (1 << 30));
    printf("mean_file_bytes\t%.0f\n", (double)total_bytes / (double)n);
    for (size_t b = 0; b < NBUCKETS; b++)
        printf("bucket\t%s\t%llu files\t%llu bytes\n", BUCKETS[b].name, (unsigned long long)hist_n[b],
               (unsigned long long)hist_bytes[b]);
    return 0;
}
