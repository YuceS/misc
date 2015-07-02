/**
 * Naive Wi-Fi management frame monitor
 *   -- noah@hack.se, 2013
 *
 * $ sudo apt-get install libsqlite3-dev sqlite3
 * $ gcc -o wimon wimon.c -ggdb -Wall -lsqlite3
 * $ sudo iw phy phy0 interface add mon0 type monitor
 * $ sudo ip link set dev mon0 up
 * $ sudo tcpdump -ttnei mon0 -s0 'type mgt and not subtype probe-resp' | ./wimon -
 *
 * Data is logged to multiple SQLite tables:
 * - nodes (id, mac, created, ping, flags, ssid)
 * - samples (node_id, created, dbm, mgmt, sa, da, ssid)
 * - log (node_id, mac, created, log)
 *
 * Depends on SQLite 3.7 for Write-Ahead Logging
 * NOTE: Journaling with WAL is not supported on network filesystems
 *
 *
 * If junk (binary-looking) SSIDs are reported, that's because
 * Windows XP leaks a bit of memory in the probe requests :(
 *
 *
 * The IEEE MAC address prefix database can be downloaded here:
 * http://standards.ieee.org/develop/regauth/oui/oui.txt
 * It may be imported to the SQLite database like this:
 * $ grep hex oui.txt | cut -b3-11,21- | ./wimon -oui -
 *
 * Example use of OUI database:
 * $ sqlite3 wimon.db \
 *  'SELECT DATETIME(created,"unixepoch","localtime"), n.mac, org
 *   FROM nodes n
 *   LEFT JOIN oui o ON UPPER(SUBSTR(n.mac, 1, 8)) = o.mac
 *   ORDER BY created DESC LIMIT 50'
 *
 * TODO:
 * Wrap 'INSERT INTO..SELECT * FROM' and 'DELETE FROM' in a transaction to allow
 * concurrent runs of this program without risking to mess up the contents of
 * the database during maintainence operations (i.e, update())
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <sqlite3.h>

/* Database file */
#define SQLITE3_NAME "wimon.db"

/* Table period, must be a multiple of hours */
#define TABLE_PERIOD (4*3600)

/* Maximum number of different (MAC) nodes to monitor */
#define MAX_NODES 512

/* Maximum number of samples (per node) to keep in memory */
#define MAX_STA_SAMPLES 1024
/* Minimum number of samples (per node) to keep in memory (when loading) */
#define MIN_STA_SAMPLES 2

/* Maximum SSID length (including terminating zero) */
#define SSID_LEN 36
#define MAC_LEN 6

/* Timeouts for periodic updates (maintainence) and reports (in seconds) */
#define PERIODIC_UPDATE	900
#define PERIODIC_REPORT 3600

/* When to consider a node "gone" ? */
#define INACTIVITY_TIMEOUT 1800
/* When to evict a "gone" node from memory, must be > INACTIVITY_TIMEOUT */
#define EVICT_TIMEOUT (3*INACTIVITY_TIMEOUT)


/* Node flags */
typedef enum {
	/* Type */
	NFL_STA = 0x01,
	NFL_AP	= 0x02,

	/* Transient flags */
	NFL_INACTIVE = 0x04,
	NFL_NEW = 0x08,
	NFL_TRANSIENT_MASK = 0x04|0x08,

	NFL_MAX = 0x10
} flags_t;

/* Management frame subtypes; IDs compatible with ieee802_11.h */
typedef enum {
	MGMT_ASSOC_REQ = 0,
	MGMT_ASSOC_RSP = 1,
	MGMT_REASSOC_REQ = 2,
	MGMT_REASSOC_RSP = 3,
	MGMT_PROBE_REQ = 4,
	MGMT_PROBE_RSP = 5,
	MGMT_BEACON = 8,
	MGMT_ATIM = 9,
	MGMT_DISASSOC = 10,
	MGMT_AUTH = 11,
	MGMT_DEAUTH = 12,
	MGMT_ACTION = 13,
	MGMT_UNKNOWN = 16
} mgmt_st_t;

/* Node description */
typedef struct station {
	/* Database ID */
	long int id;

	/* MAC address */
	unsigned char mac[6];

	/* AP SSID or (guessed) associated SSID */
	char current_ssid[SSID_LEN];

	/* Node flags */
	flags_t flags;

	/* Last seen */
	time_t created;
	time_t ping;

	/* Sample counter */
	int sample;
	/* Number of samples stored to DB */
	int stored_samples;

	/* Sample data */
	struct timeval tv[MAX_STA_SAMPLES];
	unsigned short freq[MAX_STA_SAMPLES];
	short dbm[MAX_STA_SAMPLES];
	mgmt_st_t mgmt[MAX_STA_SAMPLES];
	char ssid[MAX_STA_SAMPLES][SSID_LEN];
	unsigned char sa[MAX_STA_SAMPLES][MAC_LEN];
	unsigned char da[MAX_STA_SAMPLES][MAC_LEN];
} sta_t;


static int num_nodes;
static sta_t nodes[MAX_NODES];
static sqlite3 *db;
static int do_exit;
static int num_prepared_stmts;
static sqlite3_stmt **prepared_stmts[6];


static const char *mactoa(const unsigned char *umac) {
	static char mac_out[2][18];
	static unsigned char counter_out;
	unsigned int i, mac[6];

	for(i = 0; i < 6; i++)
		mac[i] = (unsigned int)umac[i];

	sprintf(mac_out[counter_out], "%02x:%02x:%02x:%02x:%02x:%02x",
	    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	/* allow mactoa() to be called twice in printf() args */
	counter_out ^= 1;
	return mac_out[counter_out ^ 1];
}

static const char *mgmttoa(const mgmt_st_t t) {
	switch(t) {
	case MGMT_ASSOC_REQ:
		return "assoc-req";
	case MGMT_ASSOC_RSP:
		return "assoc-resp";
	case MGMT_REASSOC_REQ:
		return "reassoc-req";
	case MGMT_REASSOC_RSP:
		return "reassoc-resp";
	case MGMT_PROBE_REQ:
		return "probe-req";
	case MGMT_PROBE_RSP:
		return "probe-resp";
	case MGMT_BEACON:
		return "beacon";
	case MGMT_ATIM:
		return "atim";
	case MGMT_DISASSOC:
		return "disassoc";
	case MGMT_AUTH:
		return "auth";
	case MGMT_DEAUTH:
		return "deauth";
	case MGMT_ACTION:
		return "action";
	case MGMT_UNKNOWN:
		return "unknown";
	}

	return "<unhandled mgmt type>";
}

static const char *nfltoa(const flags_t flags) {
	static char flags_out[128];
	int i, n;

	strcpy(flags_out, "");
	for(n = 0, i = 1; i < NFL_MAX; i <<= 1) {
		if((flags & i) == 0)
			continue;

		if(n++)
			strcat(flags_out, ",");

		switch(flags & i) {
		case NFL_STA:
			strcat(flags_out, "STA");
			break;
		case NFL_AP:
			strcat(flags_out, " AP");
			break;
		case NFL_INACTIVE:
			strcat(flags_out, "GON");
			break;
		case NFL_NEW:
			strcat(flags_out, "NEW");
			break;
		default:
			strcat(flags_out, "BUG");
			break;
		}

		n++;
	}

	return flags_out;
}

static void register_db_stmt(sqlite3_stmt **stmt) {
	prepared_stmts[num_prepared_stmts++] = stmt;
	assert(num_prepared_stmts <= sizeof(prepared_stmts)/sizeof(prepared_stmts[0]));
}

static void unregister_db_stmts(void) {
	while(num_prepared_stmts--) {
		sqlite3_finalize(*(prepared_stmts[num_prepared_stmts]));
		*(prepared_stmts[num_prepared_stmts]) = NULL;
	}
}

/* Create necessary tables and indexes */
static int create_db_tables(time_t now) {
	char q[512];
	struct tm tm;


	now -= now % TABLE_PERIOD;
	gmtime_r(&now, &tm);

	sprintf(q, "CREATE TABLE IF NOT EXISTS nodes"
			" (id INTEGER PRIMARY KEY ASC AUTOINCREMENT, mac TEXT,"
			" created UNSIGNED INTEGER, ping UNSIGNED INTEGER,"
			" flags UNSIGNED INTEGER, ssid TEXT)");
	if(sqlite3_exec(db, q, NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "SQLite: %s\nSQL: %s\n", sqlite3_errmsg(db), q);
		return -1;
	}

	sprintf(q, "CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_mac"
		" ON nodes (mac ASC)");
	if(sqlite3_exec(db, q, NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "SQLite: %s\nSQL: %s\n", sqlite3_errmsg(db), q);
		return -1;
	}


	sprintf(q, "CREATE TABLE IF NOT EXISTS samples (node_id INTEGER,"
		" created UNSIGNED integer, freq INTEGER, dbm INTEGER,"
		" mgmt INTEGER, da TEXT, sa TEXT, ssid TEXT)");
	if(sqlite3_exec(db, q, NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "SQLite: %s\nSQL: %s\n", sqlite3_errmsg(db), q);
		return -1;
	}

	sprintf(q, "CREATE INDEX IF NOT EXISTS idx_samples_node_id"
		" ON samples (node_id ASC)");
	if(sqlite3_exec(db, q, NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "SQLite: %s\nSQL: %s\n", sqlite3_errmsg(db), q);
		return -1;
	}

	sprintf(q, "CREATE INDEX IF NOT EXISTS idx_samples_created"
		" ON samples (created DESC)");
	if(sqlite3_exec(db, q, NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "SQLite: %s\nSQL: %s\n", sqlite3_errmsg(db), q);
		return -1;
	}


	sprintf(q, "CREATE TABLE IF NOT EXISTS samples_%04d%02d%02d%02d"
		" (node_id INTEGER,"
		" created UNSIGNED integer, freq INTEGER, dbm INTEGER,"
		" mgmt INTEGER, da TEXT, sa TEXT, ssid TEXT)",
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour);
	if(sqlite3_exec(db, q, NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "SQLite: %s\nSQL: %s\n", sqlite3_errmsg(db), q);
		return -1;
	}

	sprintf(q, "CREATE INDEX IF NOT EXISTS idx_samples_node_id_%04d%02d%02d%02d"
		" ON samples_%04d%02d%02d%02d (node_id ASC)",
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour);
	if(sqlite3_exec(db, q, NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "SQLite: %s\nSQL: %s\n", sqlite3_errmsg(db), q);
		return -1;
	}

	sprintf(q, "CREATE INDEX IF NOT EXISTS idx_samples_created_%04d%02d%02d%02d"
		" ON samples_%04d%02d%02d%02d (created DESC)",
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour);
	if(sqlite3_exec(db, q, NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "SQLite: %s\nSQL: %s\n", sqlite3_errmsg(db), q);
		return -1;
	}


	sprintf(q, "CREATE TABLE IF NOT EXISTS log (node_id INTEGER, mac TEXT,"
		" created UNSIGNED INTEGER, log TEXT)");
	if(sqlite3_exec(db, q, NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "SQLite: %s\nSQL: %s\n", sqlite3_errmsg(db), q);
		return -1;
	}

	sprintf(q, "CREATE INDEX IF NOT EXISTS idx_log_node_id"
		" ON log (node_id ASC)");
	if(sqlite3_exec(db, q, NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "SQLite: %s\nSQL: %s\n", sqlite3_errmsg(db), q);
		return -1;
	}

	sprintf(q, "CREATE INDEX IF NOT EXISTS idx_log_created"
		" ON log (created DESC)");
	if(sqlite3_exec(db, q, NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "SQLite: %s\nSQL: %s\n", sqlite3_errmsg(db), q);
		return -1;
	}


	sprintf(q, "CREATE TABLE IF NOT EXISTS log_%04d%02d%02d%02d"
		" (node_id INTEGER, mac TEXT,"
		" created UNSIGNED INTEGER, log TEXT)",
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour);
	if(sqlite3_exec(db, q, NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "SQLite: %s\nSQL: %s\n", sqlite3_errmsg(db), q);
		return -1;
	}

	sprintf(q, "CREATE INDEX IF NOT EXISTS idx_log_node_id_%04d%02d%02d%02d"
		" ON log_%04d%02d%02d%02d (node_id ASC)",
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour);
	if(sqlite3_exec(db, q, NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "SQLite: %s\nSQL: %s\n", sqlite3_errmsg(db), q);
		return -1;
	}

	sprintf(q, "CREATE INDEX IF NOT EXISTS idx_log_created_%04d%02d%02d%02d"
		" ON log_%04d%02d%02d%02d (created DESC)",
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour);
	if(sqlite3_exec(db, q, NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "SQLite: %s\nSQL: %s\n", sqlite3_errmsg(db), q);
		return -1;
	}


	sprintf(q, "CREATE TABLE IF NOT EXISTS ssidlog "
		" (ssid TEXT, mac TEXT, ping UNSIGNED INTEGER, "
		" mgmt UNSIGNED INTEGER, PRIMARY KEY (ssid, mac))");
	if(sqlite3_exec(db, q, NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "SQLite: %s\nSQL: %s\n", sqlite3_errmsg(db), q);
		return -1;
	}

	sprintf(q, "CREATE TABLE IF NOT EXISTS oui"
		" (mac TEXT PRIMARY KEY, org TEXT)");
	if(sqlite3_exec(db, q, NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "SQLite: %s\nSQL: %s\n", sqlite3_errmsg(db), q);
		return -1;
	}

	sprintf(q, "CREATE TABLE IF NOT EXISTS stats"
		" (node_id UNSIGNED INTEGER, datehour UNSIGNED INTEGER,"
		"date UNSIGNED INTEGER, hour UNSIGNED INTEGER,"
		"mgmt UNSIGNED INTEGER, samples UNSIGNED INTEGER,"
		"PRIMARY KEY(node_id, datehour, mgmt))");
	if(sqlite3_exec(db, q, NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "SQLite: %s\nSQL: %s\n", sqlite3_errmsg(db), q);
		return -1;
	}

	return 0;
}

static int log_ssid_frame(sta_t *sta) {
	static sqlite3_stmt *stmt;
	int i, rc;

	if(stmt == NULL) {
		rc = sqlite3_prepare_v2(db,
			"REPLACE INTO ssidlog (ssid,mac,ping,mgmt)"
			" VALUES(?,?,?,?)", -1, &stmt, NULL);
		if(rc != SQLITE_OK) {
			fprintf(stderr, "[log_ssid_frame] SQLite: %s\n", sqlite3_errmsg(db));
			return -1;
		}

		register_db_stmt(&stmt);
	}

	rc = sqlite3_reset(stmt);
	if(rc != SQLITE_OK) {
		fprintf(stderr, "[log_ssid_frame] SQLite: %s\n", sqlite3_errmsg(db));
		return -1;
	}

	i = sta->sample - 1;
	sqlite3_bind_text(stmt, 1, sta->ssid[i], -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, mactoa(sta->sa[i]), -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 3, sta->ping);
	sqlite3_bind_int(stmt, 4, sta->mgmt[i]);
	while((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
		if(rc == SQLITE_BUSY) {
			usleep(1000);
			continue;
		}

		fprintf(stderr, "[log_ssid_frame] SQLite: %s\n", sqlite3_errmsg(db));
		sqlite3_reset(stmt);
		return -1;
	}

	return 0;
}

static int archive_data(time_t now) {
	int n, rc;
	struct timeval tv0, tv;
	time_t t, t_end;
	sqlite3_stmt *stmt;
	struct tm tm, tm_end;
	char date[20], date_end[20], q[256];

	gettimeofday(&tv0, NULL);

	n = 0;
	rc = sqlite3_prepare_v2(db,
		"SELECT IFNULL(MIN(created), 0) FROM samples", -1, &stmt, NULL);
	if(rc != SQLITE_OK) {
		fprintf(stderr, "[archive_data] SQLite: %s\n",
			sqlite3_errmsg(db));
		return -1;
	}

	t = 0;
	while((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
		if(rc == SQLITE_BUSY) {
			usleep(1000);
			continue;
		}
		else if(rc != SQLITE_ROW) {
			fprintf(stderr, "[archive_data] SQLite (count): %s\n",
				sqlite3_errmsg(db));
			sqlite3_finalize(stmt);
			return -1;
		}

		t = sqlite3_column_int64(stmt, 0);
	}

	sqlite3_finalize(stmt);

	if(t > 0 && (now - t) > TABLE_PERIOD) {
		/* Archive data for that particular day */
		t -= t % TABLE_PERIOD;
		gmtime_r(&t, &tm);
		strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", &tm);

		t_end = t + TABLE_PERIOD - 1;
		if((now - t_end) < TABLE_PERIOD)
			t_end = now - TABLE_PERIOD;

		gmtime_r(&t_end, &tm_end);
		strftime(date_end, sizeof(date_end), "%H:%M:%S", &tm_end);

		fprintf(stderr, "[archive_data] Archiving samples"
			" between %s - %s\n", date, date_end);

		/* Create archive tables if necessary */
		create_db_tables(t);

		sprintf(q, "INSERT INTO samples_%04d%02d%02d%02d"
			" SELECT * FROM samples WHERE created BETWEEN ? AND ?",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour);
		rc = sqlite3_prepare_v2(db, q, -1, &stmt, NULL);
		if(rc != SQLITE_OK) {
			fprintf(stderr, "[archive_data] SQLite (samples): %s\n",
				sqlite3_errmsg(db));
			return -1;
		}

		sqlite3_bind_int64(stmt, 1, t);
		sqlite3_bind_int64(stmt, 2, t_end);
		while((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
			if(rc == SQLITE_BUSY) {
				usleep(1000);
				continue;
			}

			fprintf(stderr, "[archive_data] SQLite (samples): %s\n",
				sqlite3_errmsg(db));
			sqlite3_finalize(stmt);
			return -1;
		}

		sqlite3_finalize(stmt);
		n += sqlite3_changes(db);

		rc = sqlite3_prepare_v2(db, "DELETE FROM samples"
			" WHERE created BETWEEN ? AND ?", -1, &stmt, NULL);
		if(rc != SQLITE_OK) {
			fprintf(stderr, "[archive_data] SQLite (samples): %s\n",
				sqlite3_errmsg(db));
			return -1;
		}

		sqlite3_bind_int64(stmt, 1, t);
		sqlite3_bind_int64(stmt, 2, t_end);
		while((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
			if(rc == SQLITE_BUSY) {
				usleep(1000);
				continue;
			}

			fprintf(stderr, "[archive_data] SQLite (samples): %s\n",
				sqlite3_errmsg(db));
			sqlite3_finalize(stmt);
			return -1;
		}

		sqlite3_finalize(stmt);

		gettimeofday(&tv, NULL);
		t = 1000 * (tv.tv_sec - tv0.tv_sec);
		t += (tv.tv_usec - tv0.tv_usec) / 1000;
		fprintf(stderr, "[archive_data] %d samples archived"
			" in %ldms\n", sqlite3_changes(db), t);
	}


	rc = sqlite3_prepare_v2(db,
		"SELECT IFNULL(MIN(created), 0) FROM log", -1, &stmt, NULL);
	if(rc != SQLITE_OK) {
		fprintf(stderr, "[archive_data] SQLite: %s\n",
			sqlite3_errmsg(db));
		return -1;
	}

	t = 0;
	while((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
		if(rc == SQLITE_BUSY) {
			usleep(1000);
			continue;
		}
		else if(rc != SQLITE_ROW) {
			fprintf(stderr, "[archive_data] SQLite (count): %s\n",
				sqlite3_errmsg(db));
			sqlite3_finalize(stmt);
			return -1;
		}

		t = sqlite3_column_int64(stmt, 0);
	}

	sqlite3_finalize(stmt);
	if(t > 0 && (now - t) > TABLE_PERIOD) {
		t -= t % TABLE_PERIOD;
		gmtime_r(&t, &tm);
		strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", &tm);

		t_end = t + TABLE_PERIOD - 1;
		if((now - t_end) < TABLE_PERIOD)
			t_end = now - TABLE_PERIOD;

		gmtime_r(&t_end, &tm_end);
		strftime(date_end, sizeof(date_end), "%H:%M:%S", &tm_end);

		fprintf(stderr, "[archive_data] Archiving logs"
			" between %s - %s\n", date, date_end);

		/* Create archive tables if necessary */
		create_db_tables(t);

		sprintf(q, "INSERT INTO log_%04d%02d%02d%02d"
			" SELECT * FROM log WHERE created BETWEEN ? AND ?",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour);
		rc = sqlite3_prepare_v2(db, q, -1, &stmt, NULL);
		if(rc != SQLITE_OK) {
			fprintf(stderr, "[archive_data] SQLite (log): %s\n",
				sqlite3_errmsg(db));
			return -1;
		}

		sqlite3_bind_int64(stmt, 1, t);
		sqlite3_bind_int64(stmt, 2, t_end);
		while((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
			if(rc == SQLITE_BUSY) {
				usleep(1000);
				continue;
			}

			fprintf(stderr, "[archive_data] SQLite (log): %s\n",
				sqlite3_errmsg(db));
			sqlite3_finalize(stmt);
			return -1;
		}

		sqlite3_finalize(stmt);
		n += sqlite3_changes(db);

		rc = sqlite3_prepare_v2(db, "DELETE FROM log"
			" WHERE created BETWEEN ? AND ?", -1, &stmt, NULL);
		if(rc != SQLITE_OK) {
			fprintf(stderr, "[archive_data] SQLite (logs): %s\n",
				sqlite3_errmsg(db));
			return -1;
		}

		sqlite3_bind_int64(stmt, 1, t);
		sqlite3_bind_int64(stmt, 2, t_end);
		while((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
			if(rc == SQLITE_BUSY) {
				usleep(1000);
				continue;
			}

			fprintf(stderr, "[archive_data] SQLite (log): %s\n",
				sqlite3_errmsg(db));
			sqlite3_finalize(stmt);
			return -1;
		}

		sqlite3_finalize(stmt);

		gettimeofday(&tv, NULL);
		t = 1000 * (tv.tv_sec - tv0.tv_sec);
		t += (tv.tv_usec - tv0.tv_usec) / 1000;
		fprintf(stderr, "[archive_data] %d log entries archived"
			" in %ldms\n", sqlite3_changes(db), t);
	}

	return n;
}

/* Insert node into database */
static int insert_node(sta_t *sta) {
	int rc;
	static sqlite3_stmt *stmt;

	if(stmt == NULL) {
		rc = sqlite3_prepare_v2(db,
			"INSERT INTO nodes (id,mac,created,ping,flags,ssid)"
			" VALUES(?,?,?,?,?,?)", -1, &stmt, NULL);
		if(rc != SQLITE_OK) {
			fprintf(stderr, "[insert_node] SQLite: %s\n", sqlite3_errmsg(db));
			return -1;
		}

		register_db_stmt(&stmt);
	}

	rc = sqlite3_reset(stmt);
	if(rc != SQLITE_OK) {
		fprintf(stderr, "[insert_node] SQLite: %s\n", sqlite3_errmsg(db));
		return -1;
	}

	if(sta->id == 0)
		sqlite3_bind_null(stmt, 1);
	else
		sqlite3_bind_int64(stmt, 1, sta->id);

	sqlite3_bind_text(stmt, 2, mactoa(sta->mac), -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 3, sta->created);
	sqlite3_bind_int64(stmt, 4, sta->ping);
	sqlite3_bind_int(stmt, 5, sta->flags);
	if(!strlen(sta->current_ssid))
		sqlite3_bind_null(stmt, 6);
	else
		sqlite3_bind_text(stmt, 6, sta->current_ssid, -1, SQLITE_STATIC);

	while((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
		if(rc == SQLITE_BUSY) {
			usleep(1000);
			continue;
		}

		fprintf(stderr, "[insert_node] SQLite: %s\n", sqlite3_errmsg(db));
		sqlite3_reset(stmt);
		return -1;
	}

	sta->id = sqlite3_last_insert_rowid(db);

	return 0;
}

/* Store node samples (timestamp, mgmt frame type, signal level, ssid) */
static int save_node_samples(sta_t *sta) {
	int i, rc, n;
	static sqlite3_stmt *stmt;
	char q[256];
	struct timeval tv0, tv;
	time_t t;

	gettimeofday(&tv0, NULL);

	if(stmt == NULL) {
		sprintf(q, "INSERT INTO samples"
			" (node_id,created,mgmt,freq,dbm,sa,da,ssid)"
			" VALUES(?,?,?,?,?,?,?,?)");

		rc = sqlite3_prepare_v2(db, q, -1, &stmt, NULL);
		if(rc != SQLITE_OK) {
			fprintf(stderr, "[save_node_samples] SQLite: %s\n", sqlite3_errmsg(db));
			return -1;
		}

		register_db_stmt(&stmt);
	}

	for(n = 0, i = sta->stored_samples; i < sta->sample; n++, i++) {
		rc = sqlite3_reset(stmt);
		if(rc != SQLITE_OK) {
			fprintf(stderr, "[save_node_samples] SQLite: %s\n",
				sqlite3_errmsg(db));
			return -1;
		}

		sqlite3_bind_int64(stmt, 1, sta->id);
		sqlite3_bind_int64(stmt, 2, sta->tv[i].tv_sec);
		sqlite3_bind_int(stmt, 3, sta->mgmt[i]);
		sqlite3_bind_int(stmt, 4, sta->freq[i]);
		sqlite3_bind_int(stmt, 5, sta->dbm[i]);
		sqlite3_bind_text(stmt, 6, mactoa(sta->sa[i]), -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(stmt, 7, mactoa(sta->da[i]), -1, SQLITE_TRANSIENT);
		if(sta->ssid[i][0] == 0)
			sqlite3_bind_null(stmt, 8);
		else
			sqlite3_bind_text(stmt, 8, sta->ssid[i], -1, SQLITE_STATIC);
		while((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
			if(rc == SQLITE_BUSY) {
				usleep(1000);
				continue;
			}

			fprintf(stderr, "[save_node_samples] SQLite: %s\n",
				sqlite3_errmsg(db));
			sqlite3_reset(stmt);
			return -1;
		}

		sta->stored_samples++;
	}

	if(sta->sample > MIN_STA_SAMPLES) {
		i = sta->sample - MIN_STA_SAMPLES;
		sta->sample = sta->stored_samples = MIN_STA_SAMPLES;
		memmove(sta->tv, &sta->tv[i], sta->sample * sizeof(sta->tv[0]));
		memmove(sta->freq, &sta->freq[i], sta->sample * sizeof(sta->freq[0]));
		memmove(sta->dbm, &sta->dbm[i], sta->sample * sizeof(sta->dbm[0]));
		memmove(sta->mgmt, &sta->mgmt[i], sta->sample * sizeof(sta->mgmt[0]));
		memmove(sta->sa, &sta->sa[i], sta->sample * MAC_LEN);
		memmove(sta->da, &sta->da[i], sta->sample * MAC_LEN);
		memmove(sta->ssid, &sta->ssid[i], sta->sample * SSID_LEN);
	}

	gettimeofday(&tv, NULL);
	t = 1000 * (tv.tv_sec - tv0.tv_sec);
	t += (tv.tv_usec - tv0.tv_usec) / 1000;
	if(t > 5)
		fprintf(stderr, "[save_node_samples] %d entries saved for"
			" node %s in %ldms (%ld samples/s)\n",
			n, mactoa(sta->mac), t, 1000 * n / t);

	return 0;
}

/* Load previously logged samples for node */
static int load_node_samples(sta_t *sta) {
	char q[256];
	const unsigned char *p;
	int rc, i, j, n, v;
	sqlite3_stmt *stmt_count, *stmt;
	struct timeval tv0, tv;
	time_t t;

	gettimeofday(&tv0, NULL);

	sprintf(q, "SELECT COUNT(*) FROM samples WHERE node_id=?");
	rc = sqlite3_prepare_v2(db, q, -1, &stmt_count, NULL);
	if(rc != SQLITE_OK) {
		fprintf(stderr, "[load_node_samples] SQLite (count): %s\n",
			sqlite3_errmsg(db));
		return -1;
	}

	n = 0;
	sqlite3_bind_int64(stmt_count, 1, sta->id);
	while((rc = sqlite3_step(stmt_count)) != SQLITE_DONE) {
		if(rc == SQLITE_BUSY) {
			usleep(1000);
			continue;
		}
		else if(rc != SQLITE_ROW) {
			fprintf(stderr, "[load_node_samples] SQLite (count node %ld): %s\n",
				sta->id, sqlite3_errmsg(db));
			sqlite3_finalize(stmt_count);
			return -1;
		}

		n = sqlite3_column_int(stmt_count, 0);
		if(n > MIN_STA_SAMPLES)
			n = MIN_STA_SAMPLES;
	}

	sqlite3_finalize(stmt_count);


	/* Load samples and update sta {} in reverse order */
	sprintf(q, "SELECT created,mgmt,freq,dbm,sa,da,ssid"
		" FROM samples WHERE node_id=?"
		" ORDER BY created DESC LIMIT %d", MIN_STA_SAMPLES);

	rc = sqlite3_prepare_v2(db, q, -1, &stmt, NULL);
	if(rc != SQLITE_OK) {
		fprintf(stderr, "[load_node_samples] SQLite (prep, node %ld): %s\n",
			sta->id, sqlite3_errmsg(db));
		return -1;
	}

	sqlite3_bind_int64(stmt, 1, sta->id);
	i = n;
	while((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
		if(rc == SQLITE_BUSY) {
			usleep(1000);
			continue;
		}
		else if(rc != SQLITE_ROW) {
			fprintf(stderr, "[load_node_samples] SQLite (node %ld): %s\n",
				sta->id, sqlite3_errmsg(db));
			sqlite3_finalize(stmt);
			return -1;
		}

		i--;
		sta->tv[i].tv_sec = (time_t)sqlite3_column_int64(stmt, 0);
		sta->tv[i].tv_usec = 0;
		sta->mgmt[i] = sqlite3_column_int(stmt, 1);
		sta->freq[i] = sqlite3_column_int(stmt, 2);
		sta->dbm[i] = sqlite3_column_int(stmt, 3);
		p = sqlite3_column_text(stmt, 4);
		for(j = 0; j < 18; j += 3) {
			sscanf((char *)&p[j], "%02x", &v);
			sta->sa[i][j / 3] = (unsigned char)v;
		}
		p = sqlite3_column_text(stmt, 5);
		for(j = 0; j < 18; j += 3) {
			sscanf((char *)&p[j], "%02x", &v);
			sta->da[i][j / 3] = (unsigned char)v;
		}

		sta->ssid[i][0] = 0;
		if((p = sqlite3_column_text(stmt, 6)) != NULL) {
			strncpy(sta->ssid[i], (char *)p, SSID_LEN);
			sta->ssid[i][SSID_LEN - 1] = 0;
		}
	}

	sta->sample = sta->stored_samples = n;
	sqlite3_finalize(stmt);

	gettimeofday(&tv, NULL);
	t = 1000 * (tv.tv_sec - tv0.tv_sec);
	t += (tv.tv_usec - tv0.tv_usec) / 1000;
	if(t > 5)
		fprintf(stderr, "[load_node_samples] Loaded %d samples for"
		" node ID %ld (%s) in %ldms\n", n, sta->id,
		mactoa(sta->mac), t);

	return 0;
}

/* Update node mac, ping time, flags and ssid */
static int save_node(sta_t *sta) {
	int rc;
	static sqlite3_stmt *stmt;
	struct timeval tv0, tv;
	time_t t;

	gettimeofday(&tv0, NULL);

	if(sta->id == 0) {
		fprintf(stderr, "[save_node] No ID set, trying to insert first\n");
		if(insert_node(sta) < 0) {
			fprintf(stderr, "[save_node] Insert failed\n");
			return -1;
		}
	}

	if(stmt == NULL) {
		rc = sqlite3_prepare_v2(db, "UPDATE nodes"
			" SET mac=?, ping=?, flags=?, ssid=? WHERE id=?",
			-1, &stmt, NULL);
		if(rc != SQLITE_OK) {
			fprintf(stderr, "[save_node] SQLite: %s\n", sqlite3_errmsg(db));
			return -1;
		}

		register_db_stmt(&stmt);
	}

	rc = sqlite3_reset(stmt);
	if(rc != SQLITE_OK) {
		fprintf(stderr, "[save_node] SQLite: %s\n", sqlite3_errmsg(db));
		return -1;
	}

	sqlite3_bind_text(stmt, 1, mactoa(sta->mac), -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 2, sta->ping);
	sqlite3_bind_int(stmt, 3, sta->flags & (~NFL_TRANSIENT_MASK));
	if(!strlen(sta->current_ssid))
		sqlite3_bind_null(stmt, 4);
	else
		sqlite3_bind_text(stmt, 4, sta->current_ssid, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 5, sta->id);

	while((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
		if(rc == SQLITE_BUSY) {
			usleep(1000);
			continue;
		}

		fprintf(stderr, "[save_node] SQLite: %s\n", sqlite3_errmsg(db));
		sqlite3_reset(stmt);
		break;
	}

	if(save_node_samples(sta) < 0) {
		fprintf(stderr, "[save_node] save_node_samples() failed\n");
		return -1;
	}

	gettimeofday(&tv, NULL);
	t = 1000 * (tv.tv_sec - tv0.tv_sec);
	t += (tv.tv_usec - tv0.tv_usec) / 1000;
	if(t > 5)
		fprintf(stderr, "[save_node] %s saved in %ldms\n",
			mactoa(sta->mac), t);

	return 0;
}

/* Get rid of specified node or oldest node if NULL arg */
static void evict_node(sta_t *sta) {
	int i, target;
	time_t oldest;
	sta_t *last;
	struct timeval tv0, tv;
	time_t t;

	gettimeofday(&tv0, NULL);

	last = &nodes[num_nodes - 1];
	if(sta == NULL) {
		oldest = last->ping;
		for(i = target = 0; i < num_nodes; i++) {
			sta = &nodes[i];
			if(sta->ping >= oldest)
				continue;

			oldest = sta->ping;
			target = i;
		}

		sta = &nodes[target];
		fprintf(stderr, "[evict_node] Killing node %s with ping %ld"
			" at idx %d, replacing with node %s with ping %ld"
			" at idx %d\n", mactoa(sta->mac), sta->ping, target,
			mactoa(last->mac), last->ping, num_nodes - 1);
	}

	save_node(sta);
	if(last != sta) {
		/* Copy last node's data to evicted node's spot */
		sta->id = last->id;
		memmove(sta->mac, last->mac, MAC_LEN);
		memmove(sta->current_ssid, last->current_ssid, SSID_LEN);
		sta->created = last->created;
		sta->ping = last->ping;
		sta->flags = last->flags;
		sta->sample = last->sample;
		sta->stored_samples = last->stored_samples;
		memmove(sta->tv, last->tv, last->sample * sizeof(sta->tv[0]));
		memmove(sta->freq, last->freq, last->sample * sizeof(sta->freq[0]));
		memmove(sta->dbm, last->dbm, last->sample * sizeof(sta->dbm[0]));
		memmove(sta->mgmt, last->mgmt, last->sample * sizeof(sta->mgmt[0]));
		memmove(sta->sa, last->sa, last->sample * MAC_LEN);
		memmove(sta->da, last->da, last->sample * MAC_LEN);
		memmove(sta->ssid, last->ssid, last->sample * SSID_LEN);
	}

	num_nodes--;

	gettimeofday(&tv, NULL);
	t = 1000 * (tv.tv_sec - tv0.tv_sec);
	t += (tv.tv_usec - tv0.tv_usec) / 1000;
	if(t > 5)
		fprintf(stderr, "[evict_node] Spent %ldms evicting node %d\n",
			t, target);
}

/* In-memory description of node */
static sta_t *alloc_node(void) {
	int i;
	sta_t *sta;

	i = num_nodes++;
	if(num_nodes == MAX_NODES) {
		evict_node(NULL);
	}

	sta = &nodes[i];
	sta->id = 0;
	memset(sta->mac, 0, MAC_LEN);
	memset(sta->current_ssid, 0, SSID_LEN);
	sta->created = sta->ping = 0;
	sta->flags = 0;
	sta->sample = 0;
	sta->stored_samples = 0;
	memset(sta->tv, 0, sizeof(sta->tv));
	memset(sta->freq, 0, sizeof(sta->freq));
	memset(sta->dbm, 0, sizeof(sta->dbm));
	memset(sta->mgmt, 0, sizeof(sta->mgmt));
	memset(sta->sa, 0, sizeof(sta->sa));
	memset(sta->da, 0, sizeof(sta->da));
	memset(sta->ssid, 0, sizeof(sta->ssid));

	return sta;
}

/**
 * Attempt to lookup node in memory.
 * If not found, attempt to lookup by MAC in database.
 * If not found, return NULL
 */
static sta_t *lookup_node(const unsigned char *sa, time_t now) {
	int rc, i, v;
	const unsigned char *p;
	static sqlite3_stmt *stmt;
	sta_t *sta;

	/* Lookup in cache */
	for(i = 0; i < num_nodes; i++) {
		sta = &nodes[i];
		if(!memcmp(sta->mac, sa, MAC_LEN))
			return sta;
	}

	/* Lookup in database */
	if(stmt == NULL) {
		rc = sqlite3_prepare_v2(db,
			"SELECT id,mac,created,ping,flags,ssid FROM nodes"
			" WHERE mac=?", -1, &stmt, NULL);
		if(rc != SQLITE_OK) {
			fprintf(stderr, "[lookup_node] SQLite: %s\n",
				sqlite3_errmsg(db));
			return NULL;
		}

		register_db_stmt(&stmt);
	}

	rc = sqlite3_reset(stmt);
	if(rc != SQLITE_OK) {
		fprintf(stderr, "[lookup_node] SQLite: %s\n", sqlite3_errmsg(db));
		return NULL;
	}

	sqlite3_bind_text(stmt, 1, mactoa(sa), -1, SQLITE_STATIC);

	sta = NULL;
	while((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
		if(rc == SQLITE_BUSY) {
			usleep(1000);
			continue;
		}
		else if(rc != SQLITE_ROW) {
			fprintf(stderr, "[lookup_node] SQLite: %s\n",
				sqlite3_errmsg(db));
			sqlite3_reset(stmt);
			return sta;
		}

		sta = alloc_node();
		sta->id = sqlite3_column_int64(stmt, 0);

		p = sqlite3_column_text(stmt, 1);
		for(i = 0; i < 18; i += 3) {
			sscanf((char *)&p[i], "%02x", &v);
			sta->mac[i / 3] = (unsigned char)v;
		}

		sta->created = (time_t)sqlite3_column_int64(stmt, 2);
		sta->ping = (time_t)sqlite3_column_int64(stmt, 3);
		sta->flags = sqlite3_column_int(stmt, 4);

		memset(sta->current_ssid, 0, SSID_LEN);
		p = sqlite3_column_text(stmt, 5);
		if(p != NULL) {
			strncpy(sta->current_ssid, (char *)p, SSID_LEN);
			sta->current_ssid[SSID_LEN - 1] = 0;
		}

		fprintf(stderr, "[lookup_node] Found node %s in SQLite\n", mactoa(sta->mac));
		if(load_node_samples(sta) == 0)
			continue;

		fprintf(stderr, "[lookup_node] Failed to load samples for id %ld\n",
			sta->id);
		sqlite3_reset(stmt);
		return sta;
	}

	return sta;
}

/* Write node_id, MAC, timestamp and msg to log table */
static int log_node_message(const sta_t *sta, const char *msg) {
	int rc;
	static sqlite3_stmt *stmt;

	puts(msg);

	if(stmt == NULL) {
		rc = sqlite3_prepare_v2(db,
			"INSERT INTO log (node_id,mac,created,log) "
			"VALUES(?,?,?,?)", -1, &stmt, NULL);
		if(rc != SQLITE_OK) {
			fprintf(stderr, "[log_node_message] SQLite: %s\n",
				sqlite3_errmsg(db));
			return -1;
		}

		register_db_stmt(&stmt);
	}

	if(sqlite3_reset(stmt) != SQLITE_OK) {
		fprintf(stderr, "[log_node_message] SQLite: %s\n",
			sqlite3_errmsg(db));
		return -1;
	}

	sqlite3_bind_int64(stmt, 1, sta->id);
	sqlite3_bind_text(stmt, 2, mactoa(sta->mac), -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 3, sta->ping);
	sqlite3_bind_text(stmt, 4, msg, -1, SQLITE_STATIC);
	while((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
		if(rc == SQLITE_BUSY) {
			usleep(1000);
			continue;
		}

		fprintf(stderr, "[log_node_message] SQLite: %s\n",
			sqlite3_errmsg(db));
		sqlite3_reset(stmt);
		return -1;
	}

	return 0;
}

static int parse_tcpdump(char *line, unsigned char *bssid, unsigned char *da,
		unsigned char *sa, unsigned short *freq, short *signal,
		struct timeval *tv, mgmt_st_t *mgmt_st, char *ssid) {

	char *p, *ws;
	size_t i, j, n, v;
	long sec, usec;
	unsigned char *m;

	n = strlen(line);
	i = 0;

	/* read time of day (tcpdump -tt format) */
	for(p = ws = &line[i]; i < n && line[i] && line[i] != ' '; i++, ws++);
	*ws = 0; if(i < n) i++;

	memset(tv, 0, sizeof(struct timeval));
	if(sscanf(p, "%ld.%ld", &sec, &usec) != 2)
		return -1;
	tv->tv_sec = sec;
	tv->tv_usec = (int)usec;

	/* locate frequency */
	while(i < n) {
		char junk[2];
		for(p = &line[i]; i < n && line[i] && line[i] != ' '; i++, p++);
		if(i < n) i++, p++;
		if(sscanf(p, "%04hu %1[M]%1[H]%1[z]", freq, junk, junk, junk) == 4)
			break;
	}

	/* locate signal strength */
	while(i < n) {
		char junk[2];
		for(p = ws = &line[i]; i < n && line[i] && line[i] != ' '; i++, ws++);
		*ws = 0; if(i < n) i++;
		if(sscanf(p, "%hd%1[d]%1[B]", signal, junk, junk) == 3)
			break;
	}

	/* locate BSSID */
	while(i < n) {
		for(p = ws = &line[i]; i < n && line[i] && line[i] != ' '; i++, ws++);
		*ws = 0; if(i < n) i++;
		if(!strncmp(p, "BSSID:", 6))
			break;
	}

	if(i == n) return -2;

	/* read BSSID MAC */
	m = memset(bssid, 0, MAC_LEN);
	p += 5;
	for(j = 0; p[j] && j < 18; j += 3, m++) {
		sscanf(p + j, ":%02zx", &v);
		*m = (unsigned char)v;
	}

	/* read DA MAC */
	for(p = ws = &line[i]; i < n && line[i] && line[i] != ' '; i++, ws++);
	*ws = 0; if(i < n) i++;
	m = memset(da, 0, MAC_LEN);
	if(strncmp("DA:", p, 3)) return -3;
	for(p += 2, j = 0; p[j] && j < 18; j += 3, m++) {
		sscanf(p + j, ":%02zx", &v);
		*m = (unsigned char)v;
	}

	/* read SA MAC */
	for(p = ws = &line[i]; i < n && line[i] && line[i] != ' '; i++, ws++);
	*ws = 0; if(i < n) i++;
	m = memset(sa, 0, MAC_LEN);
	if(strncmp("SA:", p, 3)) return -4;
	for(p += 2, j = 0; p[j] && j < 18; j += 3, m++) {
		sscanf(p + j, ":%02zx", &v);
		*m = (unsigned char)v;
	}

	/* read frame subtype */
	for(p = ws = &line[i]; i < n && line[i] && line[i] != ' '; i++, ws++);
	*ws = 0; if(i < n) i++;
	if(!strcmp(p, "Beacon")) {
		*mgmt_st = MGMT_BEACON;
	}
	else if(!strcmp(p, "Disassociation:")) {
		*mgmt_st = MGMT_DISASSOC;
	}
	else if(!strcmp(p, "DeAuthentication:")) {
		*mgmt_st = MGMT_DEAUTH;
	}
	else {
		*ws = ' ';
		for(ws = &line[i]; i < n && line[i] && line[i] != ' '; i++, ws++);
		*ws = 0; if(i < n) i++;

		if(!strcmp(p, "Probe Request")) *mgmt_st = MGMT_PROBE_REQ;
		else if(!strcmp(p, "Probe Response")) *mgmt_st = MGMT_PROBE_RSP;
		else if(!strcmp(p, "Authentication")) *mgmt_st = MGMT_AUTH;
		else if(!strcmp(p, "Assoc Request")) *mgmt_st = MGMT_ASSOC_REQ;
		else if(!strcmp(p, "Assoc Response")) *mgmt_st = MGMT_ASSOC_RSP;
		else if(!strcmp(p, "ReAssoc Request")) *mgmt_st = MGMT_REASSOC_REQ;
		else if(!strcmp(p, "ReAssoc Response")) *mgmt_st = MGMT_REASSOC_RSP;
		else *mgmt_st = MGMT_UNKNOWN;
	}

	for(p = ws = &line[i]; i < n && line[i] && line[i] != ')'; i++, ws++);
	*ws = 0; if(i < n) i++;

	ssid[0] = 0;
	if(*mgmt_st == MGMT_UNKNOWN || i == n || *p++ != '(')
		return 0;

	/* Some frame types doesn't have SSID */
	if(*mgmt_st == MGMT_ASSOC_RSP || *mgmt_st == MGMT_AUTH
		|| *mgmt_st == MGMT_DEAUTH || *mgmt_st == MGMT_DISASSOC) {

		return 0;
	}

	strncpy(ssid, p, SSID_LEN);
	ssid[SSID_LEN - 1] = 0;

	return 0;
}

#define FMT_PREFIX "%-17s %04huMHz %-3ddBm [%-7s] '%-18.18s'  "
static int process_frame(const unsigned char *bssid, const unsigned char *da,
			const unsigned char *sa, const unsigned short freq,
			const short signal, const struct timeval *tv,
			mgmt_st_t mgmt_st, const char *ssid) {
	char msg[1024];
	int i;
	time_t t;
	sta_t *sta;

	if(mgmt_st == MGMT_UNKNOWN)
		return 0;

	sta = lookup_node(sa, tv->tv_sec);
	if(sta != NULL) {
		if(tv->tv_sec - (sta->ping + INACTIVITY_TIMEOUT) > 0) {
			sta->flags |= NFL_INACTIVE;
		}
	}
	else {
		sta = alloc_node();
		memcpy(sta->mac, sa, MAC_LEN);
		sta->created = sta->ping = tv->tv_sec;
		if(insert_node(sta) < 0) {
			fprintf(stderr, "[process_frame] insert_node() failed\n");
			return -1;
		}

		sta->flags |= NFL_NEW;
	}

	/* Update node flags */
	if(mgmt_st == MGMT_BEACON || mgmt_st == MGMT_PROBE_RSP
		|| mgmt_st == MGMT_ASSOC_RSP
		|| mgmt_st == MGMT_REASSOC_RSP || mgmt_st == MGMT_DEAUTH
		|| (mgmt_st == MGMT_DISASSOC && !memcmp(sa, bssid, 6))) {

		sta->flags |= NFL_AP;
		if(sta->flags & NFL_STA) {
			fprintf(stderr, "[process_frame] BUG: Got %s frame for station %s\n",
				mgmttoa(mgmt_st), mactoa(sta->mac));
			sta->flags &= ~NFL_STA;
		}

		/* Update SSID for APs */
		if(mgmt_st == MGMT_BEACON) {
			strncpy(sta->current_ssid, ssid, SSID_LEN);
			sta->current_ssid[SSID_LEN - 1] = 0;
		}
	}
	else {
		sta->flags |= NFL_STA;
		if(sta->flags & NFL_AP) {
			fprintf(stderr, "[process_frame] BUG: Got %s frame for AP %s\n",
				mgmttoa(mgmt_st), mactoa(sta->mac));
			sta->flags &= ~NFL_AP;
		}
	}

	/* Ignore update if nothing changed */
	i = sta->sample - 1;
	if(i >= 0 && tv->tv_sec == sta->tv[i].tv_sec
		&& signal == sta->dbm[i]
		&& mgmt_st == sta->mgmt[i]
		&& !memcmp(sa, sta->sa[i], MAC_LEN)
		&& !memcmp(da, sta->da[i], MAC_LEN)
		&& !strcmp(ssid, sta->ssid[i])) {

		/* Update ping */
		sta->ping = tv->tv_sec;
		return 0;
	}

	/* Collect frame sample */
	if(sta->sample + 1 == MAX_STA_SAMPLES) {
		/* Store pending samples and evict old ones */
		save_node_samples(sta);
	}

	i = sta->sample++;
	memcpy(&sta->tv[i], tv, sizeof(struct timeval));
	sta->freq[i] = freq;
	sta->dbm[i] = signal;
	sta->mgmt[i] = mgmt_st;
	memcpy(sta->sa[i], sa, MAC_LEN);
	memcpy(sta->da[i], da, MAC_LEN);
	strncpy(sta->ssid[i], ssid, SSID_LEN);
	sta->ssid[i][SSID_LEN-1] = 0;


	if(sta->flags & NFL_NEW) {
		/* Report newly discovered nodes */
		sta->flags &= ~NFL_NEW;

		sprintf(msg, FMT_PREFIX "New %s discovered doing %s at: %s",
			mactoa(sta->mac), freq, signal,
			nfltoa(sta->flags), ssid,
			sta->flags & NFL_AP? "AP": "station",
			mgmttoa(mgmt_st), ctime(&sta->created));
		msg[strlen(msg) - 1] = 0;
		log_node_message(sta, msg);
	}
	else if(sta->flags & NFL_INACTIVE) {
		/* Report re-appearing nodes */
		sta->flags &= ~NFL_INACTIVE;

		t = tv->tv_sec - sta->ping;
		sprintf(msg, FMT_PREFIX "%s re-appeared doing %s after"
			" being gone for %ldh%02ldm: %s",
			mactoa(sta->mac), freq, signal,
			nfltoa(sta->flags), ssid,
			sta->flags & NFL_AP? "AP": "Station", mgmttoa(mgmt_st),
			t / 3600, (t % 3600) / 60, ctime(&tv->tv_sec));
		msg[strlen(msg) - 1] = 0;
		log_node_message(sta, msg);
	}


	/* Report associations */
	if(mgmt_st == MGMT_ASSOC_REQ || mgmt_st == MGMT_REASSOC_REQ
		|| mgmt_st == MGMT_AUTH) {
		sprintf(msg, FMT_PREFIX "Station attempting %s with AP %s at: %s",
			mactoa(sta->mac), freq, signal,
			nfltoa(sta->flags), ssid, mgmttoa(mgmt_st), mactoa(da),
			ctime(&tv->tv_sec));
		msg[strlen(msg) - 1] = 0;
		log_node_message(sta, msg);

		/* XXX - we're not actually sure these reqs will succeed */
		strncpy(sta->current_ssid, ssid, SSID_LEN);
		sta->current_ssid[SSID_LEN - 1] = 0;
	}
	else if(mgmt_st == MGMT_ASSOC_RSP || mgmt_st == MGMT_REASSOC_RSP
		|| mgmt_st == MGMT_PROBE_RSP || mgmt_st == MGMT_DEAUTH) {
		sprintf(msg, FMT_PREFIX "AP sent %s to station %s at: %s",
			mactoa(sta->mac), freq, signal,
			nfltoa(sta->flags), sta->current_ssid,
			mgmttoa(mgmt_st), mactoa(da), ctime(&tv->tv_sec));
		msg[strlen(msg) - 1] = 0;
		log_node_message(sta, msg);
	}
	else if(mgmt_st == MGMT_DISASSOC) {
		sprintf(msg, FMT_PREFIX "%s disassociated with %s %s at: %s",
			mactoa(sta->mac), freq, signal,
			nfltoa(sta->flags), sta->current_ssid,
			sta->flags & NFL_AP? "AP": "Station",
			sta->flags & NFL_AP? "station": "AP", mactoa(da),
			ctime(&tv->tv_sec));
		msg[strlen(msg) - 1] = 0;
		log_node_message(sta, msg);

		memset(sta->current_ssid, 0, SSID_LEN);
	}
	else if(mgmt_st == MGMT_PROBE_REQ && strlen(ssid)) {
		sprintf(msg, FMT_PREFIX "%s probing for SSID '%s' at: %s",
			mactoa(sta->mac), freq, signal,
			nfltoa(sta->flags), sta->current_ssid,
			sta->flags & NFL_AP? "AP": "Station",
			ssid, ctime(&tv->tv_sec));
		msg[strlen(msg) - 1] = 0;
		log_node_message(sta, msg);
	}

	/* Report changes in SSID probes */
	if(i && strcmp(sta->ssid[i - 1], ssid) && sta->ssid[i - 1][0] && ssid[0]) {
		sprintf(msg, FMT_PREFIX "Station previously sent %s for other SSID: %s",
			mactoa(sta->mac), freq, signal,
			nfltoa(sta->flags), sta->current_ssid,
			mgmttoa(sta->mgmt[i - 1]), sta->ssid[i - 1]);
		log_node_message(sta, msg);
	}

	/* Update ping */
	sta->ping = tv->tv_sec;

	/* log SSID */
	if(ssid[0] != 0)
		log_ssid_frame(sta);

	/**
	 * detect changes in signal quality.
	 * a 3dB change is approximately twice the change..
	 * for whatever reason it seems common that the signal ratio
	 * changes for up to ten units..?
	 */
	if(i && (signal > (sta->dbm[i - 1] + 12) || signal < (sta->dbm[i - 1] - 12))) {
		sprintf(msg, FMT_PREFIX "Signal changed %ddBm from previous value: %-3ddBm",
			mactoa(sta->mac), freq, signal,
			nfltoa(sta->flags), ssid, signal - sta->dbm[i - 1],
			sta->dbm[i - 1]);
		log_node_message(sta, msg);
	}

	return 0;
}

static int update(time_t now) {
	int i;
	sta_t *sta;
	char msg[1024];
	struct timeval tv0, tv;
	time_t t;

	gettimeofday(&tv0, NULL);
	for(i = 0; i < num_nodes; i++) {
		sta = &nodes[i];

		/* Save pending samples */
		if(save_node(sta) < 0) {
			fprintf(stderr, "[update] save_node() failed\n");
			return -1;
		}

		/* Skip recently active nodes */
		if((sta->ping + INACTIVITY_TIMEOUT) - now > 0)
			continue;

		if(now - (sta->ping + EVICT_TIMEOUT) > 0) {
			evict_node(sta);
			i--;
			continue;
		}

		/* Skip already inactive nodes */
		if(sta->flags & NFL_INACTIVE)
			continue;

		/* Mark as inactive */
		sta->flags |= NFL_INACTIVE;

		t = now - sta->ping;
		sprintf(msg, FMT_PREFIX "%s disappeared after %ldh%02ldm, last seen at: %s",
			mactoa(sta->mac), sta->freq[sta->sample - 1],
			sta->dbm[sta->sample - 1],
			nfltoa(sta->flags), sta->ssid[sta->sample - 1],
			sta->flags & NFL_AP? "AP": "Station",
			t / 3600, (t % 3600) / 60, ctime(&sta->ping));
		msg[strlen(msg) - 1] = 0;
		puts(msg);
		log_node_message(sta, msg);
	}

	gettimeofday(&tv, NULL);
	t = 1000 * (tv.tv_sec - tv0.tv_sec);
	t += (tv.tv_usec - tv0.tv_usec) / 1000;
	if(t > 5)
		fprintf(stderr, "[update] Spent %ldms doing node updates\n", t);

	if(archive_data(now) < 0) {
		fprintf(stderr, "[update] archive_data() failed\n");
		return -1;
	}

	/* Flush write-ahead log (no-op if not using WAL) */
	gettimeofday(&tv0, NULL);
	sqlite3_wal_checkpoint_v2(db, NULL, SQLITE_CHECKPOINT_RESTART, NULL, NULL);
	gettimeofday(&tv, NULL);
	t = 1000 * (tv.tv_sec - tv0.tv_sec);
	t += (tv.tv_usec - tv0.tv_usec) / 1000;
	if(t > 5)
		fprintf(stderr, "[update] SQLite checkpoint took %ldms\n", t);

	return 0;
}

static void do_report(void) {
	int i;
	sta_t *sta;
	time_t now = time(NULL);

	fprintf(stderr, "-- PERIODIC: %d nodes cached in memory\n", num_nodes);
	for(i = 0; i < num_nodes; i++) {
		sta = &nodes[i];
		printf(FMT_PREFIX "logged %d samples, last seen: %s",
			mactoa(sta->mac), sta->freq[sta->sample - 1],
			sta->dbm[sta->sample - 1],
			nfltoa(sta->flags), sta->current_ssid,
			sta->sample, ctime(&sta->ping));
	}

	fprintf(stderr, "-- PERIODIC: End of report at: %s\n", ctime(&now));
}

static void sighandler(int signo) {
	switch(signo) {
	case SIGUSR1:
		do_report();
		break;
	case SIGINT:
	case SIGTERM:
		fprintf(stderr, "[main] Shutting down gracefully...\n");
		do_exit = 1;
		break;
	default:
		break;
	}
}

static int oui_import(FILE *fd) {
	char buf[1024], *hex, *org, *p;
	int rc;
	sqlite3_stmt *stmt;

	rc = sqlite3_prepare_v2(db, "INSERT INTO oui VALUES(?,?)", -1, &stmt, NULL);
	if(rc != SQLITE_OK) {
		fprintf(stderr, "[oui_import] SQLite: %s\n", sqlite3_errmsg(db));
		return -1;
	}

	while(fgets(buf, sizeof(buf), fd)) {
		hex = buf;
		for(p = hex; *p && *p != ' '; p++) if(*p == '-') *p = ':';
		*p = 0;

		org = ++p;
		for(; *p && *p != '\r' && *p != '\n'; p++);
		*p = 0;

		if(sqlite3_reset(stmt) != SQLITE_OK) {
			fprintf(stderr, "[oui_import] SQLite: %s\n", sqlite3_errmsg(db));
		}

		sqlite3_bind_text(stmt, 1, hex, -1, SQLITE_STATIC);
		sqlite3_bind_text(stmt, 2, org, -1, SQLITE_STATIC);
		while((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
			if(rc == SQLITE_BUSY) {
				usleep(1000);
				continue;
			}

			fprintf(stderr, "[oui_import] SQLite: %s\n", sqlite3_errmsg(db));
			fprintf(stderr, "[out_import] Offending MAC: %s\n", hex);
			sqlite3_reset(stmt);
			break;
		}
	}

	sqlite3_finalize(stmt);

	return 0;
}

int main(int c, char **v) {
	char buf[512], ssid[SSID_LEN];
	unsigned char bssid[MAC_LEN], da[MAC_LEN], sa[MAC_LEN];
	unsigned short freq;
	short dbm;
	int n;
	struct timeval tv;
	mgmt_st_t mgmt_st;
	time_t now, prev_report, prev_update;
	FILE *fd;

	if(c < 2) {
		fprintf(stderr, "Usage: %s [-oui] <file>\n", v[0]);
		fprintf(stderr, "\t-oui Import OUI database (see header)\n");
		fprintf(stderr, "\t<file> Read data from file (or - for stdin)\n");
		return -1;
	}

	fprintf(stderr, "Memory: Using %zd MiBytes RAM for in-memory stations"
		"(%d stations, up to %d samples/station)\n",
		sizeof(nodes) / 1024 / 1024, MAX_NODES, MAX_STA_SAMPLES);

	fprintf(stderr, "SQLite: Opening database %s\n", SQLITE3_NAME);
	if(sqlite3_open(SQLITE3_NAME, &db)) {
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return -1;
	}

	/**
	 * SQLite performance tuning
	 * - mmap() up to 16MB (mmap_size)
	 * - 32MB cache size (cache_size)
	 * - Use WAL; set to "OFF" if you don't care about data consistency
	 * - Use "NORMAL" sync; works great with WAL; may be set to "0" (OFF)
	 */
	sqlite3_exec(db, "PRAGMA mmap_size=16777216", NULL, NULL, NULL);
	sqlite3_exec(db, "PRAGMA cache_size=-32768", NULL, NULL, NULL);
	sqlite3_exec(db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);

	fprintf(stderr, "SQLite: Initializing tables\n");
	now = time(NULL);
	create_db_tables(now);

	fprintf(stderr, "SQLite: Archiving old data\n");
	do {
		n = archive_data(now);
		if(n < 0) {
			sqlite3_close(db);
			return -1;
		}
	} while(n > 0);

	sqlite3_exec(db, "PRAGMA synchronous=1", NULL, NULL, NULL);

	fd = stdin;
	if(strcmp(v[c - 1], "-")) {
		fd = fopen(v[c - 1], "r");
		if(fd == NULL) {
			fprintf(stderr, "[main] Error opening file: %s\n",
				v[c - 1]);
			sqlite3_close(db);
			return -1;
		}
	}

	if(!strcmp(v[1], "-oui")) {
		fprintf(stderr, "[main] Importing OUI database...\n");
		oui_import(fd);
		fclose(fd);
		sqlite3_close(db);
		return 0;
	}

	signal(SIGTERM, sighandler);
	signal(SIGINT, sighandler);
	/* Hook SIGUSR1 to provide reports on demand */
	signal(SIGUSR1, sighandler);

	fprintf(stderr, "[main] Parsing tcpdump output for Wi-Fi frames...\n");
	prev_report = prev_update = time(NULL);
	while(!do_exit && fgets(buf, sizeof(buf), fd) != NULL) {
		char *temp;

		/* Parse tcpdump output */
		temp = strdup(buf);
		if((n = parse_tcpdump(buf,
			bssid, da, sa, &freq, &dbm, &tv, &mgmt_st, ssid)) < 0) {

			fprintf(stderr, "[main] parse_tcpdump() failed: %d\n"
				"tcpdump data: %s", n, temp);
			free(temp);
			continue;
		}

		free(temp);

		if(process_frame(bssid, da, sa, freq, dbm, &tv, mgmt_st, ssid)) {
			fprintf(stderr, "[main] process_frame() failed\n");
			break;
		}

		now = tv.tv_sec;
		if(now - (prev_update + PERIODIC_UPDATE) > 0) {
			sqlite3_exec(db, "PRAGMA synchronous=0", NULL, NULL, NULL);
			if(update(now) < 0) {
				fprintf(stderr, "[main] update() failed\n");
				break;
			}
			prev_update = now;
			sqlite3_exec(db, "PRAGMA synchronous=1", NULL, NULL, NULL);
		}

		if(now - (prev_report + PERIODIC_REPORT) > 0) {
			do_report();
			prev_report = now;
		}
	}

	fclose(fd);

	/* Do a final update and save everything */
	sqlite3_exec(db, "PRAGMA synchronous=0", NULL, NULL, NULL);
	sqlite3_exec(db, "PRAGMA journal_mode=OFF", NULL, NULL, NULL);
	update(time(NULL));
	unregister_db_stmts();
	sqlite3_close(db);

	return 0;
}
