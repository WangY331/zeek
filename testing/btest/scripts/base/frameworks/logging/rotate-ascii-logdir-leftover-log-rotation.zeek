# @TEST-DOC: Enable leftover log rotation and logdir. Note, files are rotated into the cwd.
# @TEST-EXEC: mkdir logs
# @TEST-EXEC: zeek -b -r ${TRACES}/rotation.trace %INPUT >zeek.out 2>&1
# @TEST-EXEC: grep "test" zeek.out | sort >out
# @TEST-EXEC: for i in `ls logs/test.*.log | sort`; do printf '> %s\n' $i; cat $i; done >>out
# @TEST-EXEC: TEST_DIFF_CANONIFIER='$SCRIPTS/diff-remove-abspath | $SCRIPTS/diff-remove-timestamps' btest-diff out

module Test;

export {
	# Create a new ID for our log stream
	redef enum Log::ID += { LOG };

	# Define a record with all the columns the log file can have.
	# (I'm using a subset of fields from ssh-ext for demonstration.)
	type Log: record {
		t: time;
		id: conn_id; # Will be rolled out into individual columns.
	} &log;
}

redef LogAscii::enable_leftover_log_rotation = T;
redef Log::default_logdir = "./logs";
redef Log::default_rotation_interval = 1hr;
redef Log::default_rotation_postprocessor_cmd = "echo";

event zeek_init()
	{
	Log::create_stream(Test::LOG, [$columns=Log]);
	}

event new_connection(c: connection)
	{
	Log::write(Test::LOG, [$t=network_time(), $id=c$id]);
	}
