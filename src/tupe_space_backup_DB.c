#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>

int backup_sqlite_db(const char *source_db_path, const char *backup_path_prefix)
{
    sqlite3 *source_db = NULL;
    sqlite3 *backup_db = NULL;
    sqlite3_backup *backup_handle = NULL;
    int rc = SQLITE_OK;
    char backup_path[256];

    // Generate backup filename with timestamp
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);

    snprintf(backup_path, sizeof(backup_path), "%s_%s.db",
             backup_path_prefix, timestamp);

    // Open source database
    rc = sqlite3_open(source_db_path, &source_db);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Cannot open source database %s: %s\n",
                source_db_path, sqlite3_errmsg(source_db));
        goto cleanup;
    }

    // Open backup database file
    rc = sqlite3_open(backup_path, &backup_db);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Cannot open backup database %s: %s\n",
                backup_path, sqlite3_errmsg(backup_db));
        goto cleanup;
    }

    // Initialize backup process
    backup_handle = sqlite3_backup_init(
        backup_db, // Destination database
        "main",    // Destination database name
        source_db, // Source database
        "main"     // Source database name
    );

    if (!backup_handle)
    {
        fprintf(stderr, "Failed to initialize backup: %s\n",
                sqlite3_errmsg(backup_db));
        rc = SQLITE_ERROR;
        goto cleanup;
    }

    // Perform the backup
    // Step through all pages (-1), with no delay between steps (0)
    rc = sqlite3_backup_step(backup_handle, -1);
    if (rc != SQLITE_DONE)
    {
        fprintf(stderr, "Backup step failed: %s\n",
                sqlite3_errmsg(backup_db));
        goto cleanup;
    }

    // Finalize the backup
    rc = sqlite3_backup_finish(backup_handle);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Backup finish failed: %s\n",
                sqlite3_errmsg(backup_db));
        goto cleanup;
    }

    printf("Database successfully backed up to %s\n", backup_path);

cleanup:
    if (backup_handle)
    {
        sqlite3_backup_finish(backup_handle);
    }
    if (backup_db)
    {
        sqlite3_close(backup_db);
    }
    if (source_db)
    {
        sqlite3_close(source_db);
    }

    return rc == SQLITE_OK ? 0 : -1;
}

// Example usage in a separate process
int main(int argc, char *argv[])
{
    const char *source_path = "/usr/local/tuple_space/sql/tuple_space.db";
    const char *backup_prefix = "/usr/local/tuple_space/sql/backup/tuple_space_backup";

    // Ensure backup directory exists (you'd need to create it beforehand)
    int result = backup_sqlite_db(source_path, backup_prefix);

    if (result != 0)
    {
        fprintf(stderr, "Backup process failed\n");
        return 1;
    }

    return 0;
}