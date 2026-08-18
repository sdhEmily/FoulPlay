#pragma once
//
// Minimal declarations for the system libarchive.
//
// iOS ships /usr/lib/libarchive.2.dylib and the SDK carries a .tbd for it, but
// Apple does not ship <archive.h>. Every symbol below is verified present in
// the SDK stub; the constants are libarchive's stable public ABI values.
//
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef int64_t  la_int64_t;
typedef ssize_t  la_ssize_t;

struct archive;
struct archive_entry;

// Return codes
#define ARCHIVE_EOF     1
#define ARCHIVE_OK      0

// archive_write_disk_set_options flags
#define ARCHIVE_EXTRACT_PERM                 0x0002
#define ARCHIVE_EXTRACT_TIME                 0x0004
#define ARCHIVE_EXTRACT_SECURE_SYMLINKS      0x0100
#define ARCHIVE_EXTRACT_SECURE_NODOTDOT      0x0200

#ifdef __cplusplus
extern "C" {
#endif

// Reading archives
struct archive *archive_read_new(void);
int  archive_read_support_format_zip(struct archive *);
int  archive_read_open_filename(struct archive *, const char *, size_t);
int  archive_read_next_header(struct archive *, struct archive_entry **);
int  archive_read_next_header2(struct archive *, struct archive_entry *);
int  archive_read_data_block(struct archive *, const void **, size_t *, la_int64_t *);
int  archive_read_close(struct archive *);
int  archive_read_free(struct archive *);

// Reading the filesystem as an archive
struct archive *archive_read_disk_new(void);
int  archive_read_disk_open(struct archive *, const char *);
int  archive_read_disk_descend(struct archive *);
int  archive_read_disk_set_symlink_physical(struct archive *);

// Writing archives
struct archive *archive_write_new(void);
int  archive_write_set_format_zip(struct archive *);
int  archive_write_set_options(struct archive *, const char *);
int  archive_write_set_bytes_per_block(struct archive *, int);
int  archive_write_zip_set_compression_store(struct archive *);
int  archive_write_zip_set_compression_deflate(struct archive *);
int  archive_write_open_filename(struct archive *, const char *);
int  archive_write_header(struct archive *, struct archive_entry *);
la_ssize_t archive_write_data(struct archive *, const void *, size_t);
int  archive_write_finish_entry(struct archive *);
int  archive_write_close(struct archive *);
int  archive_write_free(struct archive *);

// Writing to disk
struct archive *archive_write_disk_new(void);
int  archive_write_disk_set_options(struct archive *, int);
la_ssize_t archive_write_data_block(struct archive *, const void *, size_t, la_int64_t);

// Entries
struct archive_entry *archive_entry_new(void);
void archive_entry_free(struct archive_entry *);
const char *archive_entry_pathname(struct archive_entry *);
void        archive_entry_set_pathname(struct archive_entry *, const char *);
const char *archive_entry_sourcepath(struct archive_entry *);
la_int64_t  archive_entry_size(struct archive_entry *);

const char *archive_error_string(struct archive *);
int  archive_errno(struct archive *);

#ifdef __cplusplus
}
#endif
