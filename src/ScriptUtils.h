// See the file "COPYING" in the main distribution directory for copyright.
#pragma once

#include <string_view>

namespace zeek
	{
class RecordVal;
class VectorVal;

template <class T> class IntrusivePtr;
using RecordValPtr = IntrusivePtr<RecordVal>;
using VectorValPtr = IntrusivePtr<VectorVal>;

namespace detail
	{
class Location;
	}
	}

namespace zeek::util::detail
	{

/**
 * Create a single BacktraceElement record val.
 *
 * @param name the name of the function.
 * @param args call argument vector created by MakeCallArgumentVector().
 * @param loc optional location information of the caller.
 *
 * @return record value representing a BacktraceElement.
 */
zeek::RecordValPtr make_backtrace_element(std::string_view name, const VectorValPtr args,
                                          const zeek::detail::Location* loc);

/**
 * Create a Zeek script Backtrace of the current script call_stack.
 *
 * @return VectorValPtr containing BacktraceElement entries.
 */
zeek::VectorValPtr get_current_script_backtrace();

	}
