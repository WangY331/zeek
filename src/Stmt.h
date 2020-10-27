// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

// BRO statements.

#include "ZeekList.h"
#include "Dict.h"
#include "ID.h"
#include "Obj.h"

#include "StmtEnums.h"

#include "TraverseTypes.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(CompositeHash, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Frame, zeek::detail);

namespace zeek::run_state { extern double network_time; }

namespace zeek::detail {

class StmtList;
class ForStmt;
class EventExpr;
class ListExpr;

using EventExprPtr = IntrusivePtr<EventExpr>;
using ListExprPtr = IntrusivePtr<ListExpr>;

class Stmt;
using StmtPtr = IntrusivePtr<Stmt>;

class Stmt : public Obj {
public:
	StmtTag Tag() const	{ return tag; }

	~Stmt() override;

	virtual ValPtr Exec(Frame* f, StmtFlowType& flow) const = 0;

	Stmt* Ref()			{ zeek::Ref(this); return this; }

	bool SetLocationInfo(const Location* loc) override
		{ return Stmt::SetLocationInfo(loc, loc); }
	bool SetLocationInfo(const Location* start, const Location* end) override;

	// True if the statement has no side effects, false otherwise.
	virtual bool IsPure() const;

	StmtList* AsStmtList();
	const StmtList* AsStmtList() const;

	ForStmt* AsForStmt();

	void RegisterAccess() const	{ last_access = run_state::network_time; access_count++; }
	void AccessStats(ODesc* d) const;
	uint32_t GetAccessCount() const { return access_count; }

	void Describe(ODesc* d) const final;

	virtual void IncrBPCount()	{ ++breakpoint_count; }
	virtual void DecrBPCount();

	virtual unsigned int BPCount() const	{ return breakpoint_count; }

	virtual TraversalCode Traverse(TraversalCallback* cb) const = 0;


	//
	// BEGINNING of methods relating to script optimization.
	//

	// Returns a duplicate of the statement so that modifications
	// can be made to statements from inlining function bodies - or
	// to the originals - without affecting other instances.
	//
	// It's tempting to think that there are some statements that
	// are safe to share across multiple functions and could just
	// return references to themselves - but since we associate
	// information such as reaching-defs with statements, even these
	// need to be duplicated.
	virtual StmtPtr Duplicate() = 0;

	// Access to the original statement from which this one is derived,
	// or this one if we don't have an original.  Returns a bare pointer
	// rather than a StmtPtr to emphasize that the access is read-only.
	const Stmt* Original() const
		{ return original ? original->Original() : this; }

	// Designate the given Stmt node as the original for this one.
	void SetOriginal(StmtPtr _orig)
		{
		if ( ! original )
			original = std::move(_orig);
		}

	// A convenience function for taking a newly-created Stmt,
	// making it point to us as the successor, and returning it.
	//
	// Takes a Stmt* rather than a StmtPtr to de-clutter the calling
	// code, which is always passing in "new XyzStmt(...)".  This
	// call, as a convenient side effect, transforms that bare pointer
	// into a StmtPtr.
	virtual StmtPtr SetSucc(Stmt* succ)
		{
		succ->SetOriginal({NewRef{}, this});
		return {AdoptRef{}, succ};
		}

	//
	// END of methods relating to script optimization.
	//

protected:
	explicit Stmt(StmtTag arg_tag);

	void AddTag(ODesc* d) const;
	virtual void StmtDescribe(ODesc* d) const;
	void DescribeDone(ODesc* d) const;

	StmtTag tag;
	int breakpoint_count;	// how many breakpoints on this statement

	// FIXME: Learn the exact semantics of mutable.
	mutable double last_access;	// time of last execution
	mutable uint32_t access_count;	// number of executions


	//
	// BEGINNING of member variables and protected methods
	// relating to script optimization.
	//

        // The original statement from which this statement was
        // derived, if any.  Used as an aid for generating meaningful
	// and correctly-localized error messages.
	StmtPtr original = nullptr;

	//
	// END of member variables and protected methods
	// relating to script optimization.
	//
};

class ExprListStmt : public Stmt {
public:
	const ListExpr* ExprList() const	{ return l.get(); }

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	ExprListStmt(StmtTag t, ListExprPtr arg_l);

	~ExprListStmt() override;

	ValPtr Exec(Frame* f, StmtFlowType& flow) const override;
	virtual ValPtr DoExec(std::vector<ValPtr> vals,
	                      StmtFlowType& flow) const = 0;

	void StmtDescribe(ODesc* d) const override;

	ListExprPtr l;
};

class PrintStmt final : public ExprListStmt {
public:
	template<typename L>
	explicit PrintStmt(L&& l) : ExprListStmt(STMT_PRINT, std::forward<L>(l)) { }

	// Optimization-related:
	StmtPtr Duplicate() override;

protected:
	ValPtr DoExec(std::vector<ValPtr> vals,
	              StmtFlowType& flow) const override;
};

class ExprStmt : public Stmt {
public:
	explicit ExprStmt(ExprPtr e);
	~ExprStmt() override;

	ValPtr Exec(Frame* f, StmtFlowType& flow) const override;

	const Expr* StmtExpr() const	{ return e.get(); }

	void StmtDescribe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	StmtPtr Duplicate() override;

protected:
	ExprStmt(StmtTag t, ExprPtr e);

	virtual ValPtr DoExec(Frame* f, Val* v, StmtFlowType& flow) const;

	bool IsPure() const override;

	ExprPtr e;
};

class IfStmt final : public ExprStmt {
public:
	IfStmt(ExprPtr test, StmtPtr s1, StmtPtr s2);
	~IfStmt() override;

	const Stmt* TrueBranch() const	{ return s1.get(); }
	const Stmt* FalseBranch() const	{ return s2.get(); }

	void StmtDescribe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	StmtPtr Duplicate() override;

protected:
	ValPtr DoExec(Frame* f, Val* v, StmtFlowType& flow) const override;
	bool IsPure() const override;

	StmtPtr s1;
	StmtPtr s2;
};

class Case final : public Obj {
public:
	Case(ListExprPtr c, IDPList* types, StmtPtr arg_s);
	~Case() override;

	const ListExpr* ExprCases() const	{ return expr_cases.get(); }
	ListExpr* ExprCases()		{ return expr_cases.get(); }

	const IDPList* TypeCases() const	{ return type_cases; }
	IDPList* TypeCases()		{ return type_cases; }

	const Stmt* Body() const	{ return s.get(); }
	Stmt* Body()			{ return s.get(); }

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const;

	// Optimization-related:
	IntrusivePtr<Case> Duplicate();

protected:
	ListExprPtr expr_cases;
	IDPList* type_cases;
	StmtPtr s;
};

using case_list = PList<Case>;

class SwitchStmt final : public ExprStmt {
public:
	SwitchStmt(ExprPtr index, case_list* cases);
	~SwitchStmt() override;

	const case_list* Cases() const	{ return cases; }

	void StmtDescribe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	StmtPtr Duplicate() override;

protected:
	ValPtr DoExec(Frame* f, Val* v, StmtFlowType& flow) const override;
	bool IsPure() const override;

	// Initialize composite hash and case label map.
	void Init();

	// Adds an entry in case_label_value_map for the given value to associate it
	// with the given index in the cases list.  If the entry already exists,
	// returns false, else returns true.
	bool AddCaseLabelValueMapping(const Val* v, int idx);

	// Adds an entry in case_label_type_map for the given type (w/ ID) to
	// associate it with the given index in the cases list.  If an entry
	// for the type already exists, returns false; else returns true.
	bool AddCaseLabelTypeMapping(ID* t, int idx);

	// Returns index of a case label that matches the value, or
	// default_case_idx if no case label matches (which may be -1 if
	// there's no default label). The second tuple element is the ID of
	// the matching type-based case if it defines one.
	std::pair<int, ID*> FindCaseLabelMatch(const Val* v) const;

	case_list* cases;
	int default_case_idx;
	CompositeHash* comp_hash;
	PDict<int> case_label_value_map;
	std::vector<std::pair<ID*, int>> case_label_type_list;
};

class AddStmt final : public ExprStmt {
public:
	explicit AddStmt(ExprPtr e);

	bool IsPure() const override;
	ValPtr Exec(Frame* f, StmtFlowType& flow) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	StmtPtr Duplicate() override;
};

class DelStmt final : public ExprStmt {
public:
	explicit DelStmt(ExprPtr e);

	bool IsPure() const override;
	ValPtr Exec(Frame* f, StmtFlowType& flow) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	StmtPtr Duplicate() override;
};

class EventStmt final : public ExprStmt {
public:
	explicit EventStmt(EventExprPtr e);

	ValPtr Exec(Frame* f, StmtFlowType& flow) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	StmtPtr Duplicate() override;

protected:
	EventExprPtr event_expr;
};

class WhileStmt final : public Stmt {
public:

	WhileStmt(ExprPtr loop_condition, StmtPtr body);
	~WhileStmt() override;

	bool IsPure() const override;

	void StmtDescribe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	StmtPtr Duplicate() override;

protected:
	ValPtr Exec(Frame* f, StmtFlowType& flow) const override;

	ExprPtr loop_condition;
	StmtPtr body;
};

class ForStmt final : public ExprStmt {
public:
	ForStmt(IDPList* loop_vars, ExprPtr loop_expr);
	// Special constructor for key value for loop.
	ForStmt(IDPList* loop_vars, ExprPtr loop_expr, IDPtr val_var);
	~ForStmt() override;

	void AddBody(StmtPtr arg_body)	{ body = std::move(arg_body); }

	const IDPList* LoopVar() const	{ return loop_vars; }
	const Expr* LoopExpr() const	{ return e.get(); }
	const Stmt* LoopBody() const	{ return body.get(); }

	bool IsPure() const override;

	void StmtDescribe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	StmtPtr Duplicate() override;

protected:
	ValPtr DoExec(Frame* f, Val* v, StmtFlowType& flow) const override;

	IDPList* loop_vars;
	StmtPtr body;
	// Stores the value variable being used for a key value for loop.
	// Always set to nullptr unless special constructor is called.
	IDPtr value_var;
};

class NextStmt final : public Stmt {
public:
	NextStmt() : Stmt(STMT_NEXT)	{ }

	ValPtr Exec(Frame* f, StmtFlowType& flow) const override;
	bool IsPure() const override;

	void StmtDescribe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	IntrusivePtr<Stmt> Duplicate() override
		{ return SetSucc(new NextStmt()); }
protected:
};

class BreakStmt final : public Stmt {
public:
	BreakStmt() : Stmt(STMT_BREAK)	{ }

	ValPtr Exec(Frame* f, StmtFlowType& flow) const override;
	bool IsPure() const override;

	void StmtDescribe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	IntrusivePtr<Stmt> Duplicate() override
		{ return SetSucc(new BreakStmt()); }

protected:
};

class FallthroughStmt final : public Stmt {
public:
	FallthroughStmt() : Stmt(STMT_FALLTHROUGH)	{ }

	ValPtr Exec(Frame* f, StmtFlowType& flow) const override;
	bool IsPure() const override;

	void StmtDescribe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	IntrusivePtr<Stmt> Duplicate() override
		{ return SetSucc(new FallthroughStmt()); }

protected:
};

class ReturnStmt final : public ExprStmt {
public:
	explicit ReturnStmt(ExprPtr e);

	ValPtr Exec(Frame* f, StmtFlowType& flow) const override;

	void StmtDescribe(ODesc* d) const override;

	// Optimization-related:
	StmtPtr Duplicate() override;

        // Constructor used for duplication, when we've already done
        // all of the type-checking.
        ReturnStmt(ExprPtr e, bool ignored);
};

class StmtList : public Stmt {
public:
	StmtList();
	~StmtList() override;

	ValPtr Exec(Frame* f, StmtFlowType& flow) const override;

	const StmtPList& Stmts() const	{ return stmts; }
	StmtPList& Stmts()		{ return stmts; }

	void StmtDescribe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	StmtPtr Duplicate() override;

protected:
	bool IsPure() const override;

	StmtPList stmts;
};

class EventBodyList final : public StmtList {
public:
	EventBodyList() : StmtList()
		{ topmost = false; tag = STMT_EVENT_BODY_LIST; }

	ValPtr Exec(Frame* f, StmtFlowType& flow) const override;

	void StmtDescribe(ODesc* d) const override;

	// "Topmost" means that this is the main body of a function or event.
	// void SetTopmost(bool is_topmost)	{ topmost = is_topmost; }
	// bool IsTopmost()	{ return topmost; }

protected:
	bool topmost;
};

class InitStmt final : public Stmt {
public:
	explicit InitStmt(std::vector<IDPtr> arg_inits);

	ValPtr Exec(Frame* f, StmtFlowType& flow) const override;

	const std::vector<IDPtr>& Inits() const
		{ return inits; }

	void StmtDescribe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	StmtPtr Duplicate() override;

protected:
	std::vector<IDPtr> inits;
};

class NullStmt final : public Stmt {
public:
	NullStmt() : Stmt(STMT_NULL)	{ }

	ValPtr Exec(Frame* f, StmtFlowType& flow) const override;
	bool IsPure() const override;

	void StmtDescribe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	IntrusivePtr<Stmt> Duplicate() override
		{ return SetSucc(new NullStmt()); }
};

class WhenStmt final : public Stmt {
public:
	// s2 is null if no timeout block given.
	WhenStmt(ExprPtr cond,
	         StmtPtr s1, StmtPtr s2,
	         ExprPtr timeout, bool is_return);
	~WhenStmt() override;

	ValPtr Exec(Frame* f, StmtFlowType& flow) const override;
	bool IsPure() const override;

	const Expr* Cond() const	{ return cond.get(); }
	const Stmt* Body() const	{ return s1.get(); }
	const Expr* TimeoutExpr() const	{ return timeout.get(); }
	const Stmt* TimeoutBody() const	{ return s2.get(); }

	void StmtDescribe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	StmtPtr Duplicate() override;

protected:
	ExprPtr cond;
	StmtPtr s1;
	StmtPtr s2;
	ExprPtr timeout;
	bool is_return;
};

} // namespace zeek::detail

using Stmt [[deprecated("Remove in v4.1. Use zeek::detail::Stmt instead.")]] = zeek::detail::Stmt;
using ExprListStmt [[deprecated("Remove in v4.1. Use zeek::detail::ExprListStmt instead.")]] = zeek::detail::ExprListStmt;
using PrintStmt [[deprecated("Remove in v4.1. Use zeek::detail::PrintStmt instead.")]] = zeek::detail::PrintStmt;
using ExprStmt [[deprecated("Remove in v4.1. Use zeek::detail::ExprStmt instead.")]] = zeek::detail::ExprStmt;
using IfStmt [[deprecated("Remove in v4.1. Use zeek::detail::IfStmt instead.")]] = zeek::detail::IfStmt;
using Case [[deprecated("Remove in v4.1. Use zeek::detail::Case instead.")]] = zeek::detail::Case;
using SwitchStmt [[deprecated("Remove in v4.1. Use zeek::detail::SwitchStmt instead.")]] = zeek::detail::SwitchStmt;
using AddStmt [[deprecated("Remove in v4.1. Use zeek::detail::AddStmt instead.")]] = zeek::detail::AddStmt;
using DelStmt [[deprecated("Remove in v4.1. Use zeek::detail::DelStmt instead.")]] = zeek::detail::DelStmt;
using EventStmt [[deprecated("Remove in v4.1. Use zeek::detail::EventStmt instead.")]] = zeek::detail::EventStmt;
using WhileStmt [[deprecated("Remove in v4.1. Use zeek::detail::WhileStmt instead.")]] = zeek::detail::WhileStmt;
using ForStmt [[deprecated("Remove in v4.1. Use zeek::detail::ForStmt instead.")]] = zeek::detail::ForStmt;
using NextStmt [[deprecated("Remove in v4.1. Use zeek::detail::NextStmt instead.")]] = zeek::detail::NextStmt;
using BreakStmt [[deprecated("Remove in v4.1. Use zeek::detail::BreakStmt instead.")]] = zeek::detail::BreakStmt;
using FallthroughStmt [[deprecated("Remove in v4.1. Use zeek::detail::FallthroughStmt instead.")]] = zeek::detail::FallthroughStmt;
using ReturnStmt [[deprecated("Remove in v4.1. Use zeek::detail::ReturnStmt instead.")]] = zeek::detail::ReturnStmt;
using StmtList [[deprecated("Remove in v4.1. Use zeek::detail::StmtList instead.")]] = zeek::detail::StmtList;
using EventBodyList [[deprecated("Remove in v4.1. Use zeek::detail::EventBodyList instead.")]] = zeek::detail::EventBodyList;
using InitStmt [[deprecated("Remove in v4.1. Use zeek::detail::InitStmt instead.")]] = zeek::detail::InitStmt;
using NullStmt [[deprecated("Remove in v4.1. Use zeek::detail::NullStmt instead.")]] = zeek::detail::NullStmt;
using WhenStmt [[deprecated("Remove in v4.1. Use zeek::detail::WhenStmt instead.")]] = zeek::detail::WhenStmt;
