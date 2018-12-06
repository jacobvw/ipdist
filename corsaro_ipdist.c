#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <yaml.h>

#include "libcorsaro3_plugin.h"
#include "libcorsaro3_avro.h"
#include "corsaro_ipdist.h"

#define CORSARO_IPDIST_MAGIC 0x3986944
#define PLUGIN_NAME "ipdist"

static corsaro_plugin_t corsaro_ipdist_plugin = {
    PLUGIN_NAME,
    CORSARO_PLUGIN_ID_IPDIST,
    CORSARO_IPDIST_MAGIC,
    CORSARO_PLUGIN_GENERATE_BASE_PTRS(corsaro_ipdist),
    CORSARO_PLUGIN_GENERATE_TRACE_PTRS(corsaro_ipdist),
    CORSARO_PLUGIN_GENERATE_MERGE_PTRS(corsaro_ipdist),
    CORSARO_PLUGIN_GENERATE_TAIL
};

static const char IPDIST_SCHEMA[] =
"{\"type\": \"record\",\
  \"namespace\": \"org.caida.corsaro\",\
  \"name\": \"ipdist\",\
  \"doc\": \"Counts source and destination IP address for each octet, \
             outputs counts for total and spoofed, erratic filters.\",\
  \"fields\": [\
        {\"name\": \"timestamp\", \"type\": \"long\"}, \
        {\"name\": \"octet\", \"type\": \"int\"}, \
        {\"name\": \"prefix\", \"type\": \"int\"}, \
        {\"name\": \"source_hits\", \"type\": \"long\"}, \
        {\"name\": \"destination_hits\", \"type\": \"long\"}, \
	{\"name\": \"filter\", \"type\": \"int\"} \
  ]}";

corsaro_plugin_t *corsaro_ipdist_alloc(void) {
    return &(corsaro_ipdist_plugin);
}

typedef struct corsaro_ipdist_config {
	/** Standard options, e.g. template **/
	corsaro_plugin_proc_options_t basic;

} corsaro_ipdist_config_t;

struct corsaro_ipdist_stats_counter_t {
	uint32_t timestamp;
	uint8_t octet;
	uint8_t prefix;
	uint64_t source_hits;
	uint64_t destination_hits;
	/* filter matched
	 * 0 - no filter
	 * 1 - spoofed filter
	 * 2 - erratic filter */
	int filter;
};

struct corsaro_ipdist_state_t {
	/* counters for each filter */
	struct corsaro_ipdist_counter_t *erratic_count;
	struct corsaro_ipdist_counter_t *spoofed_count;
	/* total counter */
	struct corsaro_ipdist_counter_t *total_count;
	/* avro writer */
	corsaro_avro_writer_t *writer;
};

struct corsaro_ipdist_counter_t {
	/* The counts for each [octet][prefix] */
        uint64_t src[4][256];
        uint64_t dst[4][256];
};

void cleanup_ipdist_state(struct corsaro_ipdist_state_t *state) {
	/* free the counters */
	free(state->erratic_count);
        free(state->spoofed_count);
        free(state->total_count);
	/* free the main structure */
        free(state);
}

static void process_ip(struct sockaddr *ip, struct corsaro_ipdist_counter_t
	*local, int dstaddr) {

	int i;

	/* Checks if the ip is of type IPv4 */
	if (ip->sa_family == AF_INET) {
		/* IPv4 - cast the generic sockaddr to a sockaddr_in */
                struct sockaddr_in *v4 = (struct sockaddr_in *)ip;
                /* Get in_addr from sockaddr */
                struct in_addr ip4 = (struct in_addr)v4->sin_addr;
                /* Ensure the address is in network byte order */
                uint32_t address = htonl(ip4.s_addr);

		/* Split the IPv4 address into each octet */
                uint8_t octet[4];
                octet[0] = (address & 0xff000000) >> 24;
                octet[1] = (address & 0x00ff0000) >> 16;
                octet[2] = (address & 0x0000ff00) >> 8;
                octet[3] = (address & 0x000000ff);

                /* check if the supplied address was a source or destination,
                 * increment the correct one */
                if(dstaddr) {
			for(i=0;i<4;i++) { local->dst[i][octet[i]] += 1; }
                } else {
                        for(i=0;i<4;i++) { local->src[i][octet[i]] += 1; }
		}
	}
}

int corsaro_ipdist_parse_config(corsaro_plugin_t *p,
	yaml_document_t *doc, yaml_node_t *options) {

	corsaro_ipdist_config_t *conf;

	conf = (corsaro_ipdist_config_t *)(malloc(sizeof(
		corsaro_ipdist_config_t)));

	p->config = conf;

	return 0;
}

int corsaro_ipdist_finalise_config(corsaro_plugin_t *p,
        corsaro_plugin_proc_options_t *stdopts, void *zmq_ctxt) {

	corsaro_ipdist_config_t *conf;
	conf = (corsaro_ipdist_config_t *)(p->config);

	conf->basic.template = stdopts->template;
	conf->basic.monitorid = stdopts->monitorid;

	return 0;
}

void corsaro_ipdist_destroy_self(corsaro_plugin_t *p) {
	corsaro_ipdist_config_t *conf;
	conf = (corsaro_ipdist_config_t *)(p->config);

	if (p->config) {
		free(p->config);
	}
	p->config = NULL;
}

static int ipdist_combine_result(struct corsaro_ipdist_state_t *combined,
	struct corsaro_ipdist_state_t *next, corsaro_logger_t *logger) {

	int i, j;
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 256; j++) {
			combined->erratic_count->src[i][j] += next->erratic_count->src[i][j];
			combined->erratic_count->dst[i][j] += next->erratic_count->dst[i][j];
			combined->spoofed_count->src[i][j] += next->spoofed_count->src[i][j];
                        combined->spoofed_count->dst[i][j] += next->spoofed_count->dst[i][j];
			combined->total_count->src[i][j] += next->total_count->src[i][j];
                        combined->total_count->dst[i][j] += next->total_count->dst[i][j];
		}
	}

	cleanup_ipdist_state(next);

	return 0;
}

static int ipdist_to_avro(corsaro_logger_t *logger, avro_value_t *av, void *counter) {

	struct corsaro_ipdist_stats_counter_t *c;
	c = (struct corsaro_ipdist_stats_counter_t *)counter;

	avro_value_t field;
	CORSARO_AVRO_SET_FIELD(long, av, field, 0, "timestamp",
		"ipdist", c->timestamp);
	CORSARO_AVRO_SET_FIELD(int, av, field, 1, "octet",
		"ipdist", c->octet);
	CORSARO_AVRO_SET_FIELD(int, av, field, 2, "prefix",
                "ipdist", c->prefix);
	CORSARO_AVRO_SET_FIELD(long, av, field, 3, "source_hits",
                "ipdist", c->source_hits);
	CORSARO_AVRO_SET_FIELD(long, av, field, 4, "destination_hits",
                "ipdist", c->destination_hits);
	CORSARO_AVRO_SET_FIELD(int, av, field, 5, "filter",
		"ipdist", c->filter);

	return 0;
}

static int write_builtin_ipdist_stats(corsaro_logger_t *logger, corsaro_avro_writer_t *writer,
	struct corsaro_ipdist_counter_t *stats, uint32_t timestamp, int filter) {

	int i, j;
	avro_value_t *avro;

	/* loop over prefix for each octet */
	for (j = 0; j < 4; j++) {
		for (i = 0; i < 256; i++) {
			struct corsaro_ipdist_stats_counter_t c;

			/* populate the stats structure for output to avro */
			c.timestamp = timestamp;
			c.octet = j+1;
			c.prefix = i;
			c.source_hits = stats->src[j][i];
			c.destination_hits = stats->dst[j][i];
			c.filter = filter;

			/* populate to avro and output */
			avro = corsaro_populate_avro_item(writer, &c, ipdist_to_avro);
			if (avro == NULL) {
				corsaro_log(logger, "Could not convert ipdist stats to "
					"avro record");
				return -1;
			}
			if (corsaro_append_avro_writer(writer, avro) < 0) {
				corsaro_log(logger, "Could not write ipdist stats to "
					"avro output file");
				return -1;
			}
		}
	}

	return 0;
}

char *corsaro_ipdist_derive_output_name(corsaro_plugin_t *p,
	void *local, uint32_t timestamp, int threadid) {

	corsaro_ipdist_config_t *conf;
	char *outputname = NULL;

	conf = (corsaro_ipdist_config_t *)(p->config);

	if (conf == NULL) {
		return NULL;
	}

	outputname = corsaro_generate_avro_file_name(conf->basic.template, p->name,
		conf->basic.monitorid, timestamp, threadid);
	if (outputname == NULL) {
		corsaro_log(p->logger, "Failed to generate suitable filename for ipdist output");
		return NULL;
	}

	return outputname;
}

int corsaro_ipdist_rotate_output(corsaro_plugin_t *p, void *local) {
	struct corsaro_ipdist_state_t *state;

	state = (struct corsaro_ipdist_state_t *)local;
	if (state == NULL) {
		return -1;
	}

	if (state->writer == NULL || corsaro_close_avro_writer(state->writer) < 0) {
		return -1;
	}

	return 0;
}

void *corsaro_ipdist_init_processing(corsaro_plugin_t *p, int threadid) {
	/* Create and initialize local thread storage */
	struct corsaro_ipdist_state_t *state = (struct corsaro_ipdist_state_t *)
		calloc(1, sizeof(struct corsaro_ipdist_state_t));

	/* allocate memory for erratic, spoofed and total counters */
	state->erratic_count = calloc(1, sizeof(struct corsaro_ipdist_counter_t));
	state->spoofed_count = calloc(1, sizeof(struct corsaro_ipdist_counter_t));
	state->total_count = calloc(1, sizeof(struct corsaro_ipdist_counter_t));

	return state;
}

int corsaro_ipdist_process_packet(corsaro_plugin_t *p, void *local,
	libtrace_packet_t *packet, corsaro_packet_tags_t *tags) {

	int i;
	/* Get local thread storage */
	struct corsaro_ipdist_state_t *state = (struct corsaro_ipdist_state_t *)local;

	struct sockaddr_storage addr;
	struct sockaddr *ip;

	/* Get the source ip address */
	ip = trace_get_source_address(packet, (struct sockaddr *)&addr);

	/* first loop over for source and then again for destination */
	for (i = 0; i < 2; i++) {
		/* If the ip was flagged as erratic add to erratic count */
		if (CORSARO_FILTERBIT_ERRATIC & tags->highlevelfilterbits) {
			if (ip != NULL) { process_ip(ip, state->erratic_count, i); }
		}
		/* If the ip was flagged as spoofed add to spoofed count */
		if (CORSARO_FILTERBIT_SPOOFED & tags->highlevelfilterbits) {
			if (ip != NULL) { process_ip(ip, state->spoofed_count, i); }
		}
		/* Always add to the total count */
		if (ip != NULL) { process_ip(ip, state->total_count, i); }

		/* Get destination address */
		ip = trace_get_destination_address(packet, (struct sockaddr *)&addr);
	}

	return 0;
}

int corsaro_ipdist_halt_processing(corsaro_plugin_t *p, void *local) {
	/* Get local thread storage */
	struct corsaro_ipdist_state_t *state = (struct corsaro_ipdist_state_t *)local;

	cleanup_ipdist_state(state);

	return 0;
}

int corsaro_ipdist_start_interval(corsaro_plugin_t *p, void *local,
	corsaro_interval_t *int_start) {

	struct corsaro_ipdist_state_t *state;
	int i, j;

	state = (struct corsaro_ipdist_state_t *)local;
	if (!state) {
		corsaro_log(p->logger, "corsaro_ipdist_start_interval : thread-"
			"local state is NULL!");
		return -1;
	}

	/* cleanup results for next interval */
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 256; j++) {
			state->erratic_count->src[i][j] = 0;
			state->erratic_count->dst[i][j] = 0;
			state->spoofed_count->src[i][j] = 0;
                        state->spoofed_count->dst[i][j] = 0;
			state->total_count->src[i][j] = 0;
                        state->total_count->dst[i][j] = 0;
		}
	}

	return 0;
}

void *corsaro_ipdist_end_interval(corsaro_plugin_t *p, void *local,
	corsaro_interval_t *int_end) {

	struct corsaro_ipdist_state_t *state, *copy;
	int i, j;

	/* Assign thread local storage to state */
	state = (struct corsaro_ipdist_state_t *)local;
	if (!state) {
		corsaro_log(p->logger, "corsaro_ipdist_end_interval: thread-"
			"local state is NULL!");
		return NULL;
	}

	/* Create structure to hold a copy of the result */
	copy = (struct corsaro_ipdist_state_t *)malloc(sizeof(
		struct corsaro_ipdist_state_t));
	copy->erratic_count = (struct corsaro_ipdist_counter_t *)malloc(sizeof(
		struct corsaro_ipdist_counter_t));
	copy->spoofed_count = (struct corsaro_ipdist_counter_t *)malloc(sizeof(
                struct corsaro_ipdist_counter_t));
	copy->total_count = (struct corsaro_ipdist_counter_t *)malloc(sizeof(
                struct corsaro_ipdist_counter_t));

	/* Copy over the results */
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 256; j++) {
			copy->erratic_count->src[i][j] = state->erratic_count->src[i][j];
			copy->erratic_count->dst[i][j] = state->erratic_count->dst[i][j];
			copy->spoofed_count->src[i][j] = state->spoofed_count->src[i][j];
                        copy->spoofed_count->dst[i][j] = state->spoofed_count->dst[i][j];
			copy->total_count->src[i][j] = state->total_count->src[i][j];
                        copy->total_count->dst[i][j] = state->total_count->dst[i][j];
		}
	}

	return (void *)copy;
}

void *corsaro_ipdist_init_merging(corsaro_plugin_t *p, int sources) {
	/* Allocate memory for tally */
	struct corsaro_ipdist_state_t *tally = (struct corsaro_ipdist_state_t *)
		calloc(1, sizeof(struct corsaro_ipdist_state_t));

	/* Allocate memory for each filters count */
	tally->erratic_count = (struct corsaro_ipdist_counter_t *)
                calloc(1, sizeof(struct corsaro_ipdist_counter_t));
	tally->spoofed_count = (struct corsaro_ipdist_counter_t *)
                calloc(1, sizeof(struct corsaro_ipdist_counter_t));
	tally->total_count = (struct corsaro_ipdist_counter_t *)
                calloc(1, sizeof(struct corsaro_ipdist_counter_t));

	/* create the avro writer */
	tally->writer = corsaro_create_avro_writer(p->logger, IPDIST_SCHEMA);

	return tally;
}

int corsaro_ipdist_merge_interval_results(corsaro_plugin_t *p,
	void *local, void **tomerge, corsaro_fin_interval_t *fin) {

	struct corsaro_ipdist_state_t *combined;
	struct corsaro_ipdist_state_t *state;
	int i, ret = 0;

	state = (struct corsaro_ipdist_state_t *)local;
	if (!state) {
		return -1;
	}

	combined = (struct corsaro_ipdist_state_t *)tomerge[0];

	/* Open avro writer if there is one and it isnt already open */
	if (state->writer && !corsaro_is_avro_writer_active(state->writer)) {
		char *outputname = p->derive_output_name(p, local, fin->timestamp, -1);
		if (outputname == NULL) {
			return -1;
		}
		if (corsaro_start_avro_writer(state->writer, outputname) == -1) {
			free(outputname);
			return -1;
		}
	}

	/* Combine all the results */
	for (i = 1; i < fin->threads_ended; i++) {
		if (ipdist_combine_result(combined, tomerge[i], p->logger) < 0) {
			corsaro_log(p->logger, "Error while merging ipdist "
				"results for thread %d", i);
			return -1;
		}
	}

	/* output erratic count */
	if (write_builtin_ipdist_stats(p->logger, state->writer, combined->erratic_count,
		fin->timestamp, 2) < 0) {
		ret = -1;
	}
	/* out spoofed count */
	if (write_builtin_ipdist_stats(p->logger, state->writer, combined->spoofed_count,
                fin->timestamp, 1) < 0) {
                ret = -1;
        }
	/* output total count */
	if (write_builtin_ipdist_stats(p->logger, state->writer, combined->total_count,
                fin->timestamp, 0) < 0) {
                ret = -1;
        }

	cleanup_ipdist_state(combined);

	return ret;

}

int corsaro_ipdist_halt_merging(corsaro_plugin_t *p, void *local) {
	struct corsaro_ipdist_state_t *tally = (struct corsaro_ipdist_state_t *)local;

	/* destroy the avro writer */
	corsaro_destroy_avro_writer(tally->writer);

	cleanup_ipdist_state(tally);

	return 0;
}
