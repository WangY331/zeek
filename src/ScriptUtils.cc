#include "ScriptUtils.h"

#include "zeek/Func.h"
#include "zeek/ID.h"
#include "zeek/Val.h"

using namespace zeek;

zeek::RecordValPtr util::detail::make_backtrace_element(std::string_view name,
                                                        const VectorValPtr args,
                                                        const zeek::detail::Location* loc)
	{
	static auto elem_type = id::find_type<RecordType>("BacktraceElement");
	static auto function_name_idx = elem_type->FieldOffset("function_name");
	static auto function_args_idx = elem_type->FieldOffset("function_args");
	static auto file_location_idx = elem_type->FieldOffset("file_location");
	static auto line_location_idx = elem_type->FieldOffset("line_location");

	auto elem = make_intrusive<RecordVal>(elem_type);
	elem->Assign(function_name_idx, name.data());
	elem->Assign(function_args_idx, std::move(args));

	if ( loc )
		{
		elem->Assign(file_location_idx, loc->filename);
		elem->Assign(line_location_idx, loc->first_line);
		}

	return elem;
	}

zeek::VectorValPtr util::detail::get_current_script_backtrace()
	{
	static auto backtrace_type = id::find_type<VectorType>("Backtrace");

	auto rval = make_intrusive<VectorVal>(backtrace_type);

	// The body of the following loop can wind up adding items to
	// the call stack (because MakeCallArgumentVector() evaluates
	// default arguments, which can in turn involve calls to script
	// functions), so we work from a copy of the current call stack
	// to prevent problems with iterator invalidation.
	auto cs_copy = zeek::detail::call_stack;

	for ( auto it = cs_copy.rbegin(); it != cs_copy.rend(); ++it )
		{
		const auto& ci = *it;
		if ( ! ci.func )
			// This happens for compiled code.
			continue;

		const auto& params = ci.func->GetType()->Params();
		auto args = MakeCallArgumentVector(ci.args, params);

		auto elem = make_backtrace_element(ci.func->Name(), std::move(args),
		                                   ci.call ? ci.call->GetLocationInfo() : nullptr);
		rval->Append(std::move(elem));
		}

	return rval;
	}
