/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_RECORD_COMMAND_H_
#define RR_RECORD_COMMAND_H_

#include "Command.h"
#include "main.h"
#include "util.h"
#include "core.h"
#include "RecordSession.h"

using namespace std;
namespace rr {

void force_close_record_session();

class RecordCommand : public Command {
public:
  virtual int run(std::vector<std::string>& args) override;

  static RecordCommand* get() { return &singleton; }

protected:
  RecordCommand(const char* name, const char* help) : Command(name, help) {}

  static RecordCommand singleton;
};
struct RecordFlags {
  vector<string> extra_env;

  /* Max counter value before the scheduler interrupts a tracee. */
  Ticks max_ticks;

  /* Whenever |ignore_sig| is pending for a tracee, decline to
   * deliver it. */
  int ignore_sig;
  /* Whenever |continue_through_sig| is delivered to a tracee, if there is no
   * user handler and the signal would terminate the program, just ignore it. */
  int continue_through_sig;

  /* Whether to use syscall buffering optimization during recording. */
  RecordSession::SyscallBuffering use_syscall_buffer;

  /* If nonzero, the desired syscall buffer size. Must be a multiple of the page
   * size.
   */
  size_t syscall_buffer_size;

  /* CPUID features to disable */
  DisableCPUIDFeatures disable_cpuid_features;

  int print_trace_dir;

  string output_trace_dir;

  /* Whether to use file-cloning optimization during recording. */
  bool use_file_cloning;

  /* Whether to use read-cloning optimization during recording. */
  bool use_read_cloning;

  /* Whether tracee processes in record and replay are allowed
   * to run on any logical CPU. */
  BindCPU bind_cpu;

  /* True if we should context switch after every rr event */
  bool always_switch;

  /* Whether to enable chaos mode in the scheduler */
  bool chaos;

  /* Controls number of cores reported to recorded process. */
  int num_cores;

  /* True if we should wait for all processes to exit before finishing
   * recording. */
  bool wait_for_all;

  /* Start child process directly if run under nested rr recording */
  NestedBehavior nested;

  bool scarce_fds;

  bool setuid_sudo;

  unique_ptr<TraceUuid> trace_id;

  /* Copy preload sources to trace dir */
  bool copy_preload_src;

  /* The signal to use for syscallbuf desched events */
  int syscallbuf_desched_sig;

  /* True if we should load the audit library for SystemTap SDT support. */
  bool stap_sdt;

  /* True if we should unmap the vdso */
  bool unmap_vdso;

  /* True if we should always enable ASAN compatibility. */
  bool asan;

  RecordFlags()
      : max_ticks(Scheduler::DEFAULT_MAX_TICKS),
        ignore_sig(0),
        continue_through_sig(0),
        use_syscall_buffer(RecordSession::ENABLE_SYSCALL_BUF),
        syscall_buffer_size(0),
        print_trace_dir(-1),
        output_trace_dir(""),
        use_file_cloning(true),
        use_read_cloning(true),
        bind_cpu(BIND_CPU),
        always_switch(false),
        chaos(false),
        num_cores(0),
        wait_for_all(false),
        nested(NESTED_ERROR),
        scarce_fds(false),
        setuid_sudo(false),
        copy_preload_src(false),
        syscallbuf_desched_sig(SYSCALLBUF_DEFAULT_DESCHED_SIGNAL),
        stap_sdt(false),
        unmap_vdso(false),
        asan(false) {}
};

} // namespace rr

#endif // RR_RECORD_COMMAND_H_
