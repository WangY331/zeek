# @TEST-DOC: Assert statement testing with assertion_hook implementation.
#
# @TEST-EXEC: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

# Hook calls break after logging out some information.
hook assertion_failure(cond: string, msg: string, bt: Backtrace)
	{
	print "assertion_failure", cond, msg, bt[0]$file_location, bt[0]$line_location;

	break;  # stop current handler
	}

event zeek_init()
	{
	assert 1 != 1;
	print "not reached";
	}

@TEST-START-NEXT
# Without break, the code continues even on assertion_failures(). I'm
# not quite sure if this isn't super dangerous, but hey :-)
hook assertion_failure(cond: string, msg: string, bt: Backtrace)
	{
	print "assertion_failure", cond, msg, bt[0];
	}

event zeek_init()
	{
	assert 1 != 1, "fall through, please (1)";
	print "this is reached (1)";
	assert 2 != 2, "fall through, please (2)";
	print "also reached (2)";
	}

@TEST-START-NEXT
# Test the backtrace location
hook assertion_failure(cond: string, msg: string, bt: Backtrace)
	{
	print "assertion_failure", cond, msg;
	local indent = "";
	for ( _, e in bt )
		{
		local file_name = e?$file_location ? e$file_location : "<none>";
		local line_number = e?$line_location ? e$line_location : 0;
		print fmt("%s%s %s:%s", indent, e$function_name, file_name, line_number);
		indent = fmt("%s ", indent);
		}

	break;  # stop current handler
	}


function f()
	{
	assert md5_hash("") == "d41d8cd98f00b204e9800998ecf8427e";
	assert to_count("5") == 4, fmt("5 is not 4");
	assert sha1_hash("") == "da39a3ee5e6b4b0d3255bfef95601890afd80709";
	}

function g() { f(); }
function h() { g(); }

event zeek_init()
	{
	h();
	print "not reached";
	}

@TEST-START-NEXT
# Calling terminate() from the assertion hook.
redef exit_only_after_terminate = T;

hook assertion_failure(cond: string, msg: string, bt: Backtrace)
	{
	print "assertion_failure", msg;
	terminate();
	}

event zeek_init()
	{
	assert F, "terminate me!";
	print "still alive!";  # terminate() is not immediate
	}

event zeek_done()
	{
	print "zeek_done()";
	assert zeek_is_terminating(), "zeek_done() should have zeek terminating";
	}

@TEST-START-NEXT
# Calling exit() from the assertion hook.
redef exit_only_after_terminate = T;

hook assertion_failure(cond: string, msg: string, bt: Backtrace)
	{
	print "assertion_failure", msg;
	exit(0);  # in real tests use exit(1), this is to please btest.
	}

event zeek_init()
	{
	assert F, "terminate me!";
	print "not reached";
	}

event zeek_done()
	{
	assert F, "zeek_done() not executed with exit()";
	}

@TEST-START-NEXT
global failures = 0;

hook assertion_failure(cond: string, msg: string, bt: Backtrace)
	{
	print fmt("assertion failure at %s:%s: %s - %s", bt[0]$file_location, bt[0]$line_location, cond, msg);

	++failures;
	}

event zeek_test()
	{
	assert md5_hash("") == "d41d8cd98f00b204e9800998ecf8427e";
	}

event zeek_test()
	{
	assert sha1_hash("") == "da39a3ee5e6b4b0d3255bfef95601890afd80709";
	}

event zeek_test()
	{
	assert sha1_hash("") == "meh";
	}

event zeek_test()
	{
	assert md5_hash("") == "muh";
	}

event zeek_init()
	{
	event zeek_test();
	}

event zeek_done()
	{
	if ( failures > 0 )
		print fmt("Had %d failed assertions", failures);

	# exit(failures > 0 ? 1 : 0);
	}
