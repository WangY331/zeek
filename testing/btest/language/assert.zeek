# @TEST-DOC: Assert statement behavior testing without an assertion_failure() hook.
#
# @TEST-EXEC-FAIL: unset ZEEK_ALLOW_INIT_ERRORS; zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

event zeek_init()
	{
	assert fmt("%s", 1) == "2";
	print "not reached";
	}

@TEST-START-NEXT
event zeek_init()
	{
	assert fmt("%s", 1) == "2", fmt("\"%s\" != \"2\"", 1);
	print "not reached";
	}

@TEST-START-NEXT
event zeek_init()
	{
	assert to_count("42") == 42.5, "always failing";
	print "not reached";
	}

@TEST-START-NEXT
event zeek_init()
	{
	local x = 2;
	assert x == 1, fmt("Expected x to be 1, have %s", x);
	print "not reached";
	}
