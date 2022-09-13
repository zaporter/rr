#include "BinaryInterface.h"
#include "GdbConnection.h"
#include "ReplayTimeline.h"
#include "main.h"

#include <cstdint>
#include <elf.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <limits>
#include <map>
#include <sstream>
#include <string>
#include <vector>
#include <iostream>

#include "BreakpointCondition.h"
#include "ElfReader.h"
#include "Event.h"
#include "GdbCommandHandler.h"
#include "GdbExpression.h"
#include "ReplaySession.h"
#include "ReplayTask.h"
#include "ScopedFd.h"
#include "StringVectorToCharArray.h"
#include "Task.h"
#include "ThreadGroup.h"
#include "core.h"
#include "kernel_metadata.h"
#include "log.h"
#include "util.h"
#include "PassthroughGdbConnection.h"

using namespace std;

namespace rr {
// ------------------------------------------------
// BEGIN PASTE FROM GdbServer.cc
// -----------------------------------------------
//
static size_t get_reg(const Registers& regs, const ExtraRegisters& extra_regs,
                      uint8_t* buf, GdbRegister regname, bool* defined) {
  size_t num_bytes = regs.read_register(buf, regname, defined);
  if (!*defined) {
    num_bytes = extra_regs.read_register(buf, regname, defined);
  }
  return num_bytes;
}

/**
 * Return the register |which|, which may not have a defined value.
 */
static GdbRegisterValue get_reg(const Registers& regs,
                                    const ExtraRegisters& extra_regs,
                                    GdbRegister which) {
  GdbRegisterValue reg;
  memset(&reg, 0, sizeof(reg));
  reg.name = which;
  reg.size = get_reg(regs, extra_regs, &reg.value[0], which, &reg.defined);
  return reg;
}

static bool set_reg(Task* target, const GdbRegisterValue& reg) {
  if (!reg.defined) {
    return false;
  }

  Registers regs = target->regs();
  if (regs.write_register(reg.name, reg.value, reg.size)) {
    target->set_regs(regs);
    return true;
  }

  ExtraRegisters extra_regs = target->extra_regs();
  if (extra_regs.write_register(reg.name, reg.value, reg.size)) {
    target->set_extra_regs(extra_regs);
    return true;
  }

  LOG(warn) << "Unhandled register name " << reg.name;
  return false;
}
static bool pid_exists(const string& trace_dir, pid_t pid) {
  TraceReader trace(trace_dir);

  while (true) {
    auto e = trace.read_task_event();
    if (e.type() == TraceTaskEvent::NONE) {
      return false;
    }
    if (e.tid() == pid) {
      return true;
    }
  }
}

static bool pid_execs(const string& trace_dir, pid_t pid) {
  TraceReader trace(trace_dir);

  while (true) {
    auto e = trace.read_task_event();
    if (e.type() == TraceTaskEvent::NONE) {
      return false;
    }
    if (e.tid() == pid && e.type() == TraceTaskEvent::EXEC) {
      return true;
    }
  }
}

static int find_pid_for_command(const string& trace_dir,
                                const string& command) {
  TraceReader trace(trace_dir);

  while (true) {
    TraceTaskEvent e = trace.read_task_event();
    if (e.type() == TraceTaskEvent::NONE) {
      return -1;
    }
    if (e.type() != TraceTaskEvent::EXEC) {
      continue;
    }
    if (e.cmd_line().empty()) {
      continue;
    }
    auto& cmd = e.cmd_line()[0];
    if (cmd == command ||
        (cmd.size() > command.size() &&
         cmd.substr(cmd.size() - command.size() - 1) == ('/' + command))) {
      return e.tid();
    }
  }
}

static GdbThreadId get_threadid(const Session& session, const TaskUid& tuid) {
  Task* t = session.find_task(tuid);
  pid_t pid = t ? t->tgid() : GdbThreadId::ANY.pid;
  return GdbThreadId(pid, tuid.tid());
}

static GdbThreadId get_threadid(Task* t) {
  return GdbThreadId(t->tgid(), t->rec_tid);
}



static bool matches_threadid(const GdbThreadId& tid,
                             const GdbThreadId& target) {
  return (target.pid <= 0 || target.pid == tid.pid) &&
         (target.tid <= 0 || target.tid == tid.tid);
}

static bool matches_threadid(Task* t, const GdbThreadId& target) {
  GdbThreadId tid = get_threadid(t);
  return matches_threadid(tid, target);
}

static WatchType watchpoint_type(GdbRequestType req) {
  switch (req) {
    case DREQ_SET_HW_BREAK:
    case DREQ_REMOVE_HW_BREAK:
      return WATCH_EXEC;
    case DREQ_SET_WR_WATCH:
    case DREQ_REMOVE_WR_WATCH:
      return WATCH_WRITE;
    case DREQ_REMOVE_RDWR_WATCH:
    case DREQ_SET_RDWR_WATCH:
    // NB: x86 doesn't support read-only watchpoints (who would
    // ever want to use one?) so we treat them as readwrite
    // watchpoints and hope that gdb can figure out what's going
    // on.  That is, if a user ever tries to set a read
    // watchpoint.
    case DREQ_REMOVE_RD_WATCH:
    case DREQ_SET_RD_WATCH:
      return WATCH_READWRITE;
    default:
      FATAL() << "Unknown dbg request " << req;
      return WatchType(-1); // not reached
  }
}

static void maybe_singlestep_for_event(Task* t, GdbRequest* req) {
  if (!t->session().is_replaying()) {
    return;
  }
  auto rt = static_cast<ReplayTask*>(t);
  if (trace_instructions_up_to_event(
          rt->session().current_trace_frame().time())) {
    fputs("Stepping: ", stderr);
    t->regs().print_register_file_compact(stderr);
    fprintf(stderr, " ticks:%" PRId64 "\n", t->tick_count());
    *req = GdbRequest(DREQ_CONT);
    req->suppress_debugger_stop = true;
    req->cont().actions.push_back(
        GdbContAction(ACTION_STEP, get_threadid(t->session(), t->tuid())));
  }
}


static bool search_memory(Task* t, const MemoryRange& where,
                          const vector<uint8_t>& find,
                          remote_ptr<void>* result) {
  vector<uint8_t> buf;
  buf.resize(page_size() + find.size() - 1);
  for (const auto& m : t->vm()->maps()) {
    MemoryRange r = MemoryRange(m.map.start(), m.map.end() + find.size() - 1)
                        .intersect(where);
    // We basically read page by page here, but we read past the end of the
    // page to handle the case where a found string crosses page boundaries.
    // This approach isn't great for handling long search strings but gdb's find
    // command isn't really suited to that.
    // Reading page by page lets us avoid problems where some pages in a
    // mapping aren't readable (e.g. reading beyond end of file).
    while (r.size() >= find.size()) {
      ssize_t nread = t->read_bytes_fallible(
          r.start(), std::min(buf.size(), r.size()), buf.data());
      if (nread >= ssize_t(find.size())) {
        void* found = memmem(buf.data(), nread, find.data(), find.size());
        if (found) {
          *result = r.start() + (static_cast<uint8_t*>(found) - buf.data());
          return true;
        }
      }
      r = MemoryRange(
          std::min(r.end(), floor_page_size(r.start()) + page_size()), r.end());
    }
  }
  return false;
}

static bool is_in_patch_stubs(Task* t, remote_code_ptr ip) {
  auto p = ip.to_data_ptr<void>();
  return t->vm()->has_mapping(p) &&
         (t->vm()->mapping_flags_of(p) & AddressSpace::Mapping::IS_PATCH_STUBS);
}

static bool any_action_targets_match(const Session& session,
                                     const TaskUid& tuid,
                                     const vector<GdbContAction>& actions) {
  GdbThreadId tid = get_threadid(session, tuid);
  return any_of(actions.begin(), actions.end(), [tid](GdbContAction action) {
    return matches_threadid(tid, action.target);
  });
}

static Task* find_first_task_matching_target(
    const Session& session, const vector<GdbContAction>& actions) {
  const Session::TaskMap& tasks = session.tasks();
  auto it = find_first_of(
      tasks.begin(), tasks.end(),
      actions.begin(), actions.end(),
      [](Session::TaskMap::value_type task_pair, GdbContAction action) {
        return matches_threadid(task_pair.second, action.target);
      });
  return it != tasks.end() ? it->second : nullptr;
}

static bool is_last_thread_exit(const BreakStatus& break_status) {
  // The task set may be empty if the task has already exited.
  return break_status.task_exit &&
         break_status.task_context.thread_group->task_set().size() <= 1;
}

static Task* is_in_exec(ReplayTimeline& timeline) {
  Task* t = timeline.current_session().current_task();
  if (!t) {
    return nullptr;
  }
  return timeline.current_session().next_step_is_successful_exec_syscall_exit()
             ? t
             : nullptr;
}

static bool target_event_reached(const ReplayTimeline& timeline, const GdbServer::Target& target, const ReplayResult& result) {
  if (target.event == -1) {
    return is_last_thread_exit(result.break_status) &&
      (target.pid <= 0 || result.break_status.task_context.thread_group->tgid == target.pid);
  } else {
    return timeline.current_session().current_trace_frame().time() > target.event;
  }
}

static uint32_t get_cpu_features(SupportedArch arch) {
  uint32_t cpu_features;
  switch (arch) {
    case x86:
    case x86_64: {
      cpu_features = arch == x86_64 ? GdbConnection::CPU_X86_64 : 0;
      unsigned int AVX_cpuid_flags = AVX_FEATURE_FLAG | OSXSAVE_FEATURE_FLAG;
      auto cpuid_data = cpuid(CPUID_GETEXTENDEDFEATURES, 0);
      if ((cpuid_data.ecx & PKU_FEATURE_FLAG) == PKU_FEATURE_FLAG) {
        // PKU (Skylake) implies AVX (Sandy Bridge).
        cpu_features |= GdbConnection::CPU_AVX | GdbConnection::CPU_PKU;
        break;
      }

      cpuid_data = cpuid(CPUID_GETFEATURES, 0);
      // We're assuming here that AVX support on the system making the recording
      // is the same as the AVX support during replay. But if that's not true,
      // rr is totally broken anyway.
      if ((cpuid_data.ecx & AVX_cpuid_flags) == AVX_cpuid_flags) {
        cpu_features |= GdbConnection::CPU_AVX;
      }
      break;
    }
    case aarch64:
      cpu_features = GdbConnection::CPU_AARCH64;
      break;
    default:
      FATAL() << "Unknown architecture";
      return 0;
  }

  return cpu_features;
}

static string to_string(const vector<string>& args) {
  stringstream ss;
  for (auto& a : args) {
    ss << "'" << a << "' ";
  }
  return ss.str();
}

static bool needs_target(const string& option) {
  return !strncmp(option.c_str(), "continue", option.size());
}

static ScopedFd generate_fake_proc_maps(Task* t) {
  TempFile file = create_temporary_file("rr-fake-proc-maps-XXXXXX");
  unlink(file.name.c_str());

  int fd = dup(file.fd);
  if (fd < 0) {
    FATAL() << "Cannot dup";
  }
  FILE* f = fdopen(fd, "w");


  int addr_min_width = word_size(t->arch()) == 8 ? 10 : 8;
  for (AddressSpace::Maps::iterator it = t->vm()->maps().begin();
       it != t->vm()->maps().end(); ++it) {
    // If this is the mapping just before the rr page and it's still librrpage,
    // merge this mapping with the subsequent one. We'd like gdb to treat
    // librrpage as the vdso, but it'll only do so if the entire vdso is one
    // mapping.
    auto m = *it;
    uintptr_t map_end = (long long)m.recorded_map.end().as_int();
    if (m.recorded_map.end() == t->vm()->rr_page_start()) {
      auto it2 = it;
      if (++it2 != t->vm()->maps().end()) {
        auto m2 = *it2;
        if (m2.flags & AddressSpace::Mapping::IS_RR_PAGE) {
          // Extend this mapping
          map_end += PRELOAD_LIBRARY_PAGE_SIZE;
          // Skip the rr page
          ++it;
        }
      }
    }

    int len =
        fprintf(f, "%0*llx-%0*llx %s%s%s%s %08llx %02x:%02x %lld",
                addr_min_width, (long long)m.recorded_map.start().as_int(),
                addr_min_width, (long long)map_end,
                (m.recorded_map.prot() & PROT_READ) ? "r" : "-",
                (m.recorded_map.prot() & PROT_WRITE) ? "w" : "-",
                (m.recorded_map.prot() & PROT_EXEC) ? "x" : "-",
                (m.recorded_map.flags() & MAP_SHARED) ? "s" : "p",
                (long long)m.recorded_map.file_offset_bytes(),
                major(m.recorded_map.device()), minor(m.recorded_map.device()),
                (long long)m.recorded_map.inode());
    while (len < 72) {
      fputc(' ', f);
      ++len;
    }
    fputc(' ', f);

    string name;
    const string& fsname = m.recorded_map.fsname();
    for (size_t i = 0; i < fsname.size(); ++i) {
      if (fsname[i] == '\n') {
        name.append("\\012");
      } else {
        name.push_back(fsname[i]);
      }
    }
    fputs(name.c_str(), f);
    fputc('\n', f);
  }
  if (ferror(f) || fclose(f)) {
    FATAL() << "Can't write";
  }

  return move(file.fd);
}

static bool is_ld_mapping(string map_name) {
  char ld_start[] = "ld-";
  size_t matchpos = map_name.find_last_of('/');
  string fname = map_name.substr(matchpos == string::npos ? 0 : matchpos + 1);
  return memcmp(fname.c_str(), ld_start,
                sizeof(ld_start)-1) == 0;
}

static bool is_likely_interp(string fsname) {
#ifdef __aarch64__
  return fsname == "/lib/ld-linux-aarch64.so.1";
#else
  return fsname == "/lib64/ld-linux-x86-64.so.2" || fsname == "/lib/ld-linux.so.2";
#endif
}

static remote_ptr<void> base_addr_from_rendezvous(Task* t, string fname)
{
  remote_ptr<void> interpreter_base = t->vm()->saved_interpreter_base();
  if (!interpreter_base || !t->vm()->has_mapping(interpreter_base)) {
    return nullptr;
  }
  string ld_path = t->vm()->saved_ld_path();
  if (ld_path.length() == 0) {
    FATAL() << "Failed to retrieve interpreter name with interpreter_base=" << interpreter_base;
  }
  ScopedFd ld(ld_path.c_str(), O_RDONLY);
  if (ld < 0) {
    FATAL() << "Open failed: " << ld_path;
  }
  ElfFileReader reader(ld);
  auto syms = reader.read_symbols(".dynsym", ".dynstr");
  static const char r_debug[] = "_r_debug";
  bool found = false;
  uintptr_t r_debug_offset = 0;
  for (size_t i = 0; i < syms.size(); ++i) {
    if (!syms.is_name(i, r_debug)) {
      continue;
    }
    r_debug_offset = syms.addr(i);
    found = true;
  }
  if (!found) {
    return nullptr;
  }
  bool ok = true;
  remote_ptr<NativeArch::r_debug> r_debug_remote = interpreter_base.as_int()+r_debug_offset;
  remote_ptr<NativeArch::link_map> link_map = t->read_mem(REMOTE_PTR_FIELD(r_debug_remote, r_map), &ok);
  while (ok && link_map != nullptr) {
    if (fname == t->read_c_str(t->read_mem(REMOTE_PTR_FIELD(link_map, l_name), &ok), &ok)) {
      remote_ptr<void> result = t->read_mem(REMOTE_PTR_FIELD(link_map, l_addr), &ok);
      return ok ? result : nullptr;
    }
    link_map = t->read_mem(REMOTE_PTR_FIELD(link_map, l_next), &ok);
  }
  return nullptr;
}
// ------------------------------------------------------
// END PASTE FROM GdbServer.cc
// ------------------------------------------------------

int64_t BinaryInterface::current_frame_time() const {
  return timeline.current_session().current_frame_time();
}

const std::vector<GdbRegisterValue>& BinaryInterface::get_regs() const{

  BinaryInterface* me = const_cast<BinaryInterface*>(this);
  Task* target =
          me->current_session().find_task(last_query_tuid);
  auto regs = target->regs();
  auto extra_regs = target->extra_regs();
  GdbRegister end;
  // Send values for all the registers we sent XML register descriptions for.
  // Those descriptions are controlled by GdbConnection::cpu_features().
  bool have_PKU = dbg->cpu_features() & GdbConnection::CPU_PKU;
  bool have_AVX = dbg->cpu_features() & GdbConnection::CPU_AVX;
  switch (regs.arch()) {
    case x86:
      end = have_PKU ? DREG_PKRU : (have_AVX ? DREG_YMM7H : DREG_ORIG_EAX);
      break;
    case x86_64:
      end = have_PKU ? DREG_64_PKRU : (have_AVX ? DREG_64_YMM15H : DREG_GS_BASE);
      break;
    case aarch64:
      end = DREG_FPCR;
      break;
    default:
      FATAL() << "Unknown architecture";
  }
  std::vector<GdbRegisterValue> rs;
  for (GdbRegister r = GdbRegister(0); r <= end; r = GdbRegister(r + 1)) {
    rs.push_back(get_reg(regs, extra_regs, r));
  }
  me->result_get_regs= rs;
  return result_get_regs;
}


bool BinaryInterface::initialize(){
  ReplayResult result;
  int i = 0;
  do {
    ++i;
    result = timeline.replay_step_forward(RUN_CONTINUE);
    if (result.status == REPLAY_EXITED) {
      //LOG(info) << "Debugger was not launched before end of trace";
      return false;
    }
  } while (!at_target(result));

  Task* t = timeline.current_session().current_task();

  debuggee_tguid = t->thread_group()->tguid();
  /* exec_file = std::string(t->vm()->exe_image().c_str()); */
  FrameTime first_run_event = std::max(t->vm()->first_run_event(),
    t->thread_group()->first_run_event());
  if (first_run_event) {
    timeline.set_reverse_execution_barrier_event(first_run_event);
  }
  //dbg = unique_ptr<GdbConnection>(new GdbConnection(t->tgid(), GdbConnection::Features()));
  dbg = unique_ptr<PassthroughGdbConnection>(new PassthroughGdbConnection(t->tgid(), GdbConnection::Features()));
  dbg->set_cpu_features(get_cpu_features(t->arch()));
  activate_debugger();
  /* dbg = await_connection(t, listen_fd, GdbConnection::Features()); */
  activate_debugger();
  return true;
}

/* After thinking about this more, I have decided that the request way is probably best 
 * This means that I need to create a request and then pass it into the debug one step function. Then I need to capture the dbg into my own. */
/*
 * Tell dbg what request to serve and then have process_debugger_requests to only do one loop and then return DREQ_NONE; Then call debug_one_step(..);
 */

// if is_processing_requests => placeholder_process_debugger_requests
//    
//    resp = run(req)
//    if resp == PASSTHROUGH {
//      last_response = resp;
//      debug_one_step();
//    }
PassthroughGdbConnection* run_req(BinaryInterface* me, GdbRequest req){
  GdbConnection* tbase = me->dbg.get();
  PassthroughGdbConnection* passthrough = static_cast<PassthroughGdbConnection*>(tbase);

  /* passthrough->set_request(req); */
  /* if (me->is_processing_requests) { */
  /*   me->last_debugger_request_result = me->placeholder_process_debugger_requests(); */
  /*   if (me->last_debugger_request_result.type == DREQ_LIBRR_PASSTHROUGH){ */
  /*     do { */
  /*       me->debug_one_step(me->last_resume_request); */
  /*     } while (!me->is_processing_requests); */
  /*   } */
    
  /* }else{ */
  /*     do { */
  /*       me->debug_one_step(me->last_resume_request); */
  /*     } while (!me->is_processing_requests); */
  /*   /1* me->debug_one_step(me->last_resume_request); *1/ */
  /* } */
  passthrough->set_request(req);
  me->last_debugger_request_result = me->placeholder_process_debugger_requests();
  if (me->last_debugger_request_result.type != DREQ_LIBRR_PASSTHROUGH){
    me->is_processing_requests=false;
  }
  int num_loops = 0;
  while(!me->is_processing_requests) {
    num_loops++;
    me->continue_or_s = me->debug_one_step(me->last_resume_request);
    me->last_debugger_request_result = GdbRequest(DREQ_LIBRR_PASSTHROUGH);
  } 
  /* GdbRequest return_request = me->last_debugger_request_result;//me->placeholder_process_debugger_requests(); */
  /* if (return_request.type != DREQ_LIBRR_PASSTHROUGH){ */
  /*   me->last_debugger_request_result = return_request; */
  /*   me->continue_or_stop = me->debug_one_step(me->last_resume_request); */
  /* } */
  assert(passthrough->has_new_val);
  return passthrough;
}

const std::string& BinaryInterface::get_exec_file() const{
  BinaryInterface* me = const_cast<BinaryInterface*>(this);
  GdbRequest req = GdbRequest(DREQ_GET_EXEC_FILE);
  Task* t = me->timeline.current_session().current_task();
  req.target.pid = req.target.tid = t->tuid().tid();
  return run_req(me,req)->val_reply_get_exec_file;
}
bool BinaryInterface::can_continue() const {
  return continue_or_s;
}

GdbThreadId BinaryInterface::get_current_thread() const{
  BinaryInterface* me = const_cast<BinaryInterface*>(this);
  GdbRequest req = GdbRequest(DREQ_GET_CURRENT_THREAD);
  return run_req(me,req)->val_reply_get_current_thread;
}

void BinaryInterface::add_pass_signal(int32_t signal){
  GdbConnection* tbase = dbg.get();
  PassthroughGdbConnection* passthrough = static_cast<PassthroughGdbConnection*>(tbase);
  passthrough->add_pass_signal(signal);

}
void BinaryInterface::clear_pass_signals(){
  GdbConnection* tbase = dbg.get();
  PassthroughGdbConnection* passthrough = static_cast<PassthroughGdbConnection*>(tbase);
  passthrough->clear_pass_signals();
}
bool BinaryInterface::has_exited() const{
  GdbConnection* tbase = dbg.get();
  PassthroughGdbConnection* passthrough = static_cast<PassthroughGdbConnection*>(tbase);
  return passthrough->has_exited;
}

bool BinaryInterface::internal_restart(GdbRestartType type, int64_t param){
  GdbConnection* tbase = dbg.get();
  PassthroughGdbConnection* passthrough = static_cast<PassthroughGdbConnection*>(tbase);
  passthrough->ran_notify_restart_failed=false;
  passthrough->ran_notify_restart=false;
  GdbRequest req = GdbRequest(DREQ_RESTART);
  req.restart().type = type;
  req.restart().param = param;
  run_req(this,req);
  return !passthrough->ran_notify_restart_failed && 
    passthrough->ran_notify_restart;

}
bool BinaryInterface::restart_from_previous(){
  return internal_restart(RESTART_FROM_PREVIOUS, -1);
}
bool BinaryInterface::restart_from_event(int64_t event){
  return internal_restart(RESTART_FROM_EVENT, event);
}
bool BinaryInterface::restart_from_ticks(int64_t ticks){
  return internal_restart(RESTART_FROM_TICKS, ticks);
}
bool BinaryInterface::restart_from_checkpoint(int64_t checkpoint){
  return internal_restart(RESTART_FROM_CHECKPOINT, checkpoint);
}

int BinaryInterface::get_exit_code() const {
  GdbConnection* tbase = dbg.get();
  PassthroughGdbConnection* passthrough = static_cast<PassthroughGdbConnection*>(tbase);
  return passthrough->exit_code;
}

const std::string& BinaryInterface::get_thread_extra_info(GdbThreadId target) const{
  BinaryInterface* me = const_cast<BinaryInterface*>(this);
  GdbRequest req = GdbRequest(DREQ_GET_THREAD_EXTRA_INFO);
  req.target = target;
  return run_req(me,req)->val_reply_get_thread_extra_info;

}

void BinaryInterface::setfs_pid(int64_t pid){
  GdbRequest req = GdbRequest(DREQ_FILE_SETFS);
  req.file_setfs().pid = pid;
  run_req(this, req);
}

bool BinaryInterface::set_symbol(const std::string& name, uintptr_t address){
  GdbRequest req = GdbRequest(DREQ_QSYMBOL);
  req.sym().address=address;
  req.sym().has_address=true;
  req.sym().name = std::string(name);
  run_req(this,req);
  return true; //TODO

}
bool BinaryInterface::set_continue_thread(GdbThreadId tid) {
  GdbRequest req = GdbRequest(DREQ_SET_CONTINUE_THREAD);
  req.target = tid;
  return run_req(this,req)->val_reply_select_thread;
}
bool BinaryInterface::set_query_thread(GdbThreadId tid) {
  GdbRequest req = GdbRequest(DREQ_SET_QUERY_THREAD);
  req.target = tid;
  return run_req(this,req)->val_reply_select_thread;
}
bool BinaryInterface::set_sw_breakpoint(uintptr_t addr, int32_t kind) {
  std::vector<std::vector<uint8_t>> conds;
  return set_breakpoint(DREQ_SET_SW_BREAK, addr, kind, conds);
}
bool BinaryInterface::remove_sw_breakpoint(uintptr_t addr, int32_t kind) {
  std::vector<std::vector<uint8_t>> conds;
  return set_breakpoint(DREQ_REMOVE_SW_BREAK, addr, kind, conds);
}
bool BinaryInterface::set_hw_breakpoint(uintptr_t addr, int32_t kind) {
  std::vector<std::vector<uint8_t>> conds;
  return set_breakpoint(DREQ_SET_HW_BREAK, addr, kind, conds);
}

bool BinaryInterface::set_breakpoint(GdbRequestType type, uintptr_t addr, int32_t kind, std::vector<std::vector<uint8_t>> conditions) {
  GdbRequest req = GdbRequest(type);
  req.watch().addr = addr;
  req.watch().kind = kind;
  req.watch().conditions = conditions;
  return run_req(this,req)->val_reply_watchpoint_request;
}
bool BinaryInterface::has_breakpoint_at_address(GdbThreadId tid, uintptr_t addr) const {
  BinaryInterface* me = const_cast<BinaryInterface*>(this);
  Task* target = me->current_session().find_task(tid.tid);
  ReplayTask* replay_task =
      me->timeline.current_session().find_task(target->tuid());
  return me->timeline.has_breakpoint_at_address(replay_task, addr);
}
const std::vector<uint8_t>& BinaryInterface::file_read(const std::string& file_name, int flags, int mode)  {
  // OPEN FILE
  GdbRequest req = GdbRequest(DREQ_FILE_OPEN);
  req.file_open().file_name = std::string(file_name);
  req.file_open().flags = flags;
  req.file_open().mode = mode;
  auto passthrough = run_req(this, req);
  int fd = passthrough->val_reply_open_fd;
  int err = passthrough->val_reply_open_err;
  if (err != 0){
    std::cout << "ERROR OPENING FILE TODO" << std::endl;
  }
  // READ FILE 
  req = GdbRequest(DREQ_FILE_PREAD);
  req.file_pread().fd = fd;
  req.file_pread().offset = 0;
  req.file_pread().size = 100000000; // Read files up to 100Mb
  passthrough = run_req(this, req);
  err = passthrough ->val_reply_pread_err;
  const std::vector<uint8_t>& bytes = passthrough->val_reply_pread_bytes;
  if (err != 0){
    std::cout << "ERROR READING FILE TODO" << std::endl;
  }
  // CLOSE FILE
  req = GdbRequest(DREQ_FILE_CLOSE);
  req.file_close().fd = fd;
  passthrough = run_req(this, req);
  err = passthrough ->val_reply_close;
  if (err != 0){
    std::cout << "ERROR CLOSING FILE TODO" << std::endl;
  }
  return bytes;
}

const std::vector<uint8_t>& BinaryInterface::get_auxv(GdbThreadId query_thread) const {
  BinaryInterface* me = const_cast<BinaryInterface*>(this);
  GdbRequest req = GdbRequest(DREQ_GET_AUXV);
  return run_req(me, req)->val_reply_get_auxv;
}
const std::vector<uint8_t>& BinaryInterface::get_mem(uintptr_t addr, uintptr_t len) const {
  BinaryInterface* me = const_cast<BinaryInterface*>(this);
  GdbRequest req = GdbRequest(DREQ_GET_MEM);
  req.target = dbg->query_thread;
  req.mem().addr = addr;
  req.mem().len = len;
  return run_req(me, req)->val_reply_get_mem;
}

GdbRequest BinaryInterface::placeholder_process_debugger_requests(ReportState state) {
    GdbRequest req = dbg->get_request();
    if (req.type==DREQ_NONE){
      return req;
    }
    req.suppress_debugger_stop = false;
    try_lazy_reverse_singlesteps(req);

    if (req.type == DREQ_READ_SIGINFO) {
      vector<uint8_t> si_bytes;
      si_bytes.resize(req.mem().len);
      memset(si_bytes.data(), 0, si_bytes.size());
      memcpy(si_bytes.data(), &stop_siginfo,
             min(si_bytes.size(), sizeof(stop_siginfo)));
      dbg->reply_read_siginfo(si_bytes);

      // READ_SIGINFO is usually the start of a diversion. It can also be
      // triggered by "print $_siginfo" but that is rare so we just assume it's
      // a diversion start; if "print $_siginfo" happens we'll print the correct
      // siginfo and then incorrectly start a diversion and go haywire :-(.
      // Ideally we'd come up with a better way to detect diversions so that
      // "print $_siginfo" works.
      req = divert(timeline.current_session());
      /* if (req.type == DREQ_NONE) { */
      /*   continue; */
      /* } */
      // Carry on to process the request that was rejected by
      // the diversion session
    }

    if (req.is_resume_request()) {
      Task* t = current_session().find_task(last_continue_tuid);
      if (t) {
        maybe_singlestep_for_event(t, &req);
      }
      return req;
    }

    if (req.type == DREQ_INTERRUPT) {
      LOG(debug) << "  request to interrupt";
      return req;
    }

    if (req.type == DREQ_RESTART) {
      // Debugger client requested that we restart execution
      // from the beginning.  Restart our debug session.
      LOG(debug) << "  request to restart at event " << req.restart().param;
      return req;
    }
    if (req.type == DREQ_DETACH) {
      LOG(debug) << "  debugger detached";
      dbg->reply_detach();
      return req;
    }

    dispatch_debugger_request(current_session(), req, state);
    return GdbRequest(DREQ_LIBRR_PASSTHROUGH);
}
// run_req 
// if is_processing_requests => placeholder_process_debugger_requests
//    
//    resp = run(req)
//    if resp == PASSTHROUGH {
//      last_response = resp;
//      debug_one_step();
//    }
//
//
//
// if not => debug_one_step()
//    if is_processing_requests {
//      is_processing_requests=false;
//      return last_response
//    }else{
  //    is_processing_requests = true
  //    rep= run(req)
  //    if rep != PASSTHROUGH => is_processing_requests=false
  //    return rep
//
//    }
//
GdbRequest BinaryInterface::process_debugger_requests(ReportState state) {
  last_debugger_request_result = placeholder_process_debugger_requests();
  is_processing_requests = last_debugger_request_result.type == DREQ_NONE;
  return last_debugger_request_result;
  /* if (!is_processing_requests){ */
  /*   is_processing_requests=false; */
  /*   return last_debugger_request_result; */
  /* }else { */
  /*   is_processing_requests = true; */
  /*   return GdbRequest(DREQ_LIBRR_PASSTHROUGH); */
  /* } */
}
/* int32_t BinaryInterface::set_sw_breakpoint(GdbThreadId target_thread) { */
/*   GdbRequest req = GdbRequest(DREQ_SET_SW_BREAK); */
/*   req.target = target_thread; */
/*   bool is_query = req.type != DREQ_SET_CONTINUE_THREAD; */
/*   Task* target = */
/*       req.target.tid > 0 */
/*           ? session.find_task(req.target.tid) */
/*           : session.find_task(is_query ? last_query_tuid : last_continue_tuid); */
/*   if (target) { */
/*     if (is_query) { */
/*       last_query_tuid = target->tuid(); */
/*     } else { */
/*       last_continue_tuid = target->tuid(); */
/*     } */
/*   } */
/* } */

std::vector<GdbThreadId> BinaryInterface::get_thread_list() const{
  BinaryInterface* me = const_cast<BinaryInterface*>(this);
  vector<GdbThreadId> tids;
  /* if (state != REPORT_THREADS_DEAD) { */
    for (auto& kv : me->current_session().tasks()) {
      tids.push_back(get_threadid(me->current_session(), kv.second->tuid()));
    }
  /* } */
  return tids;

}
const GdbRegisterValue& BinaryInterface::get_register(GdbRegister reg_name, GdbThreadId query_thread) const{
  BinaryInterface* me = const_cast<BinaryInterface*>(this);
  GdbRequest req = GdbRequest(DREQ_GET_REG);
  req.target = query_thread;
  req.reg().name = reg_name;
  return run_req(me, req)->val_reply_get_reg;
}
int32_t BinaryInterface::continue_forward(GdbContAction action) {
  vector<GdbContAction> actions;
  actions.push_back(action);
  GdbRequest req = GdbRequest(DREQ_CONT);
  req.cont().run_direction = RUN_FORWARD;
  req.cont().actions = move(actions);
  return run_req(this,req)->val_notify_stop_sig;
}
int32_t BinaryInterface::continue_backward(GdbContAction action) {
  vector<GdbContAction> actions;
  actions.push_back(action);
  GdbRequest req = GdbRequest(DREQ_CONT);
  req.cont().run_direction = RUN_BACKWARD;
  req.cont().actions = move(actions);
  return run_req(this,req)->val_notify_stop_sig;
}
/* rust::String BinaryInterface::get_exec_file(GdbThreadId request_target) const { */

/*     string exec_file; */
/*     BinaryInterface* me = const_cast<BinaryInterface*>(this); */

/*     Task* t = nullptr; */
/*     cout << "1" << endl; */
/*     if (request_target.tid) { */
/*       ThreadGroup* tg = me->current_session().find_thread_group(request_target.tid); */
/*       cout << "2" << endl; */
/*       if (tg) { */
/*         t = *tg->task_set().begin(); */
/*         cout << "3" << endl; */
/*       } */
/*     } */ 
/*     if (t) { */
/*       cout << "4" << endl; */
/*       return t->vm()->exe_image(); */
/*     } else { */
/*       return string(""); */
/*     } */
/* } */
/* /1* bool set_query_thread(GdbThreadId query_thread){ *1/ */

/* /1*   bool is_query = false; *1/ */
/* /1*   Task* target = *1/ */
/* /1*       query_thread.tid > 0 *1/ */
/* /1*           ? current_session().find_task(query_thread.tid) *1/ */
/* /1*           : current_session().find_task(is_query ? last_query_tuid : last_continue_tuid); *1/ */

/* /1*   if (target) { *1/ */
/* /1*     if (is_query) { *1/ */
/* /1*       last_query_tuid = target->tuid(); *1/ */
/* /1*     } else { *1/ */
/* /1*       last_continue_tuid = target->tuid(); *1/ */
/* /1*     } *1/ */
/* /1*   } *1/ */
/* /1*   return true; *1/ */
/* /1* } *1/ */

/* rust::Vec<GdbRegisterValue> BinaryInterface::get_regs(pid_t tid) const{ */
/*     BinaryInterface* me = const_cast<BinaryInterface*>(this); */

/*   if (tid==0){ */
/*     // TODO throw error */
/*     // */
/*   } */
/*   bool is_query = true; */
/*   Task* target = */
/*       tid > 0 */
/*           ? me->current_session().find_task(tid) */
/*           : me->current_session().find_task(is_query ? last_query_tuid : last_continue_tuid); */
/*   const Registers& regs = target->regs(); */
/*   const ExtraRegisters& extra_regs = target->extra_regs(); */
/*   GdbRegister end; */
/*   // Send values for all the registers we sent XML register descriptions for. */
/*   // Those descriptions are controlled by GdbConnection::cpu_features(). */
/*   bool have_PKU = dbg->cpu_features() & GdbConnection::CPU_PKU; */
/*   bool have_AVX = dbg->cpu_features() & GdbConnection::CPU_AVX; */
/*   switch (regs.arch()) { */
/*     case x86: */
/*       end = have_PKU ? DREG_PKRU : (have_AVX ? DREG_YMM7H : DREG_ORIG_EAX); */
/*       break; */
/*     case x86_64: */
/*       end = have_PKU ? DREG_64_PKRU : (have_AVX ? DREG_64_YMM15H : DREG_GS_BASE); */
/*       break; */
/*     case aarch64: */
/*       end = DREG_FPCR; */
/*       break; */
/*     default: */
/*       FATAL() << "Unknown architecture"; */
/*   } */
/*   rust::Vec<GdbRegisterValue> rs; */
/*   for (GdbRegister r = GdbRegister(0); r <= end; r = GdbRegister(r + 1)) { */
/*     rs.push_back(get_reg(regs, extra_regs, r)); */
/*   } */
/*     return rs; */


/* } */

static ReplaySession::Flags session_flags(const ReplayFlags& flags) {
  ReplaySession::Flags result;
  result.redirect_stdio = flags.redirect;
  result.redirect_stdio_file = flags.tty;
  result.share_private_mappings = flags.share_private_mappings;
  result.cpu_unbound = flags.cpu_unbound;
  return result;
}

static pid_t waiting_for_child;


static void handle_SIGINT_in_parent(int sig) {
 // DEBUG_ASSERT(sig == SIGINT);
  // Just ignore it.
}

static GdbServer* server_ptr = nullptr;

static void handle_SIGINT_in_child(int sig) {
  //DEBUG_ASSERT(sig == SIGINT);
  if (server_ptr) {
    server_ptr->interrupt_replay_to_target();
  }
}


std::unique_ptr<BinaryInterface> new_binary_interface_librr(int64_t target_event, const string& trace_dir){
  ReplayFlags flags;
  flags.goto_event = target_event;

  GdbServer::Target target;
  switch (flags.process_created_how) {
    case ReplayFlags::CREATED_EXEC:
      target.pid = flags.target_process;
      target.require_exec = true;
      break;
    case ReplayFlags::CREATED_FORK:
      target.pid = flags.target_process;
      target.require_exec = false;
      break;
    case ReplayFlags::CREATED_NONE:
      break;
  }
  target.event = flags.goto_event;
  auto session = ReplaySession::create(trace_dir, session_flags(flags));
  return std::unique_ptr<BinaryInterface>(new BinaryInterface(session,target));
  /* return std::make_unique<BinaryInterface>(BinaryInterface(session,target)); */
}

static int replay_2(const string& trace_dir, const ReplayFlags& flags) {
  GdbServer::Target target;
  switch (flags.process_created_how) {
    case ReplayFlags::CREATED_EXEC:
      target.pid = flags.target_process;
      target.require_exec = true;
      break;
    case ReplayFlags::CREATED_FORK:
      target.pid = flags.target_process;
      target.require_exec = false;
      break;
    case ReplayFlags::CREATED_NONE:
      break;
  }
  target.event = flags.goto_event;

  // If we're not going to autolaunch the debugger, don't go
  // through the rigamarole to set that up.  All it does is
  // complicate the process tree and confuse users.

  /* int debugger_params_pipe[2]; */
  /* if (pipe2(debugger_params_pipe, O_CLOEXEC)) { */
  /*   FATAL() << "Couldn't open debugger params pipe."; */
  /* } */
  /* if (0 == (waiting_for_child = fork())) { */
    // Ensure only the parent has the read end of the pipe open. Then if
    // the parent dies, our writes to the pipe will error out.
    /* close(debugger_params_pipe[0]); */

    {
      /* prctl(PR_SET_PDEATHSIG, SIGTERM, 0, 0, 0); */

      /* ScopedFd debugger_params_write_pipe(debugger_params_pipe[1]); */
      auto session = ReplaySession::create(trace_dir, session_flags(flags));
      GdbServer::ConnectionFlags conn_flags;
      /* conn_flags.dbg_port = flags.dbg_port; */
      /* conn_flags.dbg_host = flags.dbg_host; */
      /* /1* conn_flags.debugger_params_write_pipe = &debugger_params_write_pipe; *1/ */
      /* conn_flags.serve_files = flags.serve_files; */
      /* if (target.event == -1 && target.pid == 0) { */
      /*   // If `replay -e` is specified without a pid, go to the exit */
      /*   // of the first process (rather than the first exit of a process). */
      /*   target.pid = session->trace_reader().peek_frame().tid(); */
      /* } */
      GdbServer server(session, target);

      /* server_ptr = &server; */
      /* struct sigaction sa; */
      /* memset(&sa, 0, sizeof(sa)); */
      /* sa.sa_flags = SA_RESTART; */
      /* sa.sa_handler = handle_SIGINT_in_child; */
      /* if (sigaction(SIGINT, &sa, nullptr)) { */
      /*   FATAL() << "Couldn't set sigaction for SIGINT."; */
      /* } */

      server.serve_replay(conn_flags);
    }
    // Everything should have been cleaned up by now.
    check_for_leaks();
    return 0;
  /* } */
  // Ensure only the child has the write end of the pipe open. Then if
  // the child dies, our reads from the pipe will return EOF.
}
void beta_test_me(){
  cout << "BETA" << endl;
  vector<string> args;
  /* args.push_back("-g 1"); */
  /* args.push_back("-a"); */
  auto command = ReplayCommand::get();
  command->run(args);
}

int start_replaying_2(ReplayFlags flags, string trace_dir){
  if (!flags.target_command.empty()) {
    flags.target_process =
        find_pid_for_command(trace_dir, flags.target_command);
    if (flags.target_process <= 0) {
      fprintf(stderr, "No process '%s' found. Try 'rr ps'.\n",
              flags.target_command.c_str());
      return 2;
    }
  }
  if (flags.process_created_how != ReplayFlags::CREATED_NONE) {
    if (!pid_exists(trace_dir, flags.target_process)) {
      fprintf(stderr, "No process %d found in trace. Try 'rr ps'.\n",
              flags.target_process);
      return 2;
    }
    if (flags.process_created_how == ReplayFlags::CREATED_EXEC &&
        !pid_execs(trace_dir, flags.target_process)) {
      fprintf(stderr, "Process %d never exec()ed. Try 'rr ps', or use "
                      "'-f'.\n",
              flags.target_process);
      return 2;
    }
  }
  if (flags.dump_interval > 0 && !flags.dont_launch_debugger) {
    fprintf(stderr, "--stats requires -a\n");
    // TODO ZACK:
    //print_help(stderr);
    return 2;
  }

  assert_prerequisites();

  if (running_under_rr()) {
    if (!Flags::get().suppress_environment_warnings) {
      fprintf(stderr, "rr: rr pid %d running under parent %d. Good luck.\n",
              getpid(), getppid());
    }
    if (trace_dir.empty()) {
      fprintf(stderr,
              "rr: No trace-dir supplied. You'll try to replay the "
              "recording of this rr and have a bad time. Bailing out.\n");
      return 3;
    }
  }

  if (flags.keep_listening && flags.dbg_port == -1) {
    fprintf(stderr,
            "Cannot use --keep-listening (-k) without --dbgport (-s).\n");
    return 4;
  }

  return replay_2(trace_dir, flags);
}
void gamma_test_me(){
  cout << "GAMMA" << endl;
  string trace_dir;
  ReplayFlags flags;
  
  
  //start_replaying_2(flags, trace_dir);
  replay_2(trace_dir,flags);
  //replay(trace_dir,flags);

}
void delta_test_me(){
  cout << "DELTA" << endl;
  /* vector<string> args; */
  /* /1* args.push_back("-g 1"); *1/ */
  /* /1* args.push_back("-a"); *1/ */
  /* auto command = ReplayCommand::get(); */
  /* command->run(args); */
}

/* void sayHi(){ */
/* cout << "FUCK THIS INTEROP" << endl; */
/* } */

} // end namespace rr
  //
