/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REPLAY_COMMAND_H_
#define RR_REPLAY_COMMAND_H_

#include "Command.h"
#include "Flags.h"
#include "GdbServer.h"
#include "ReplaySession.h"
#include "core.h"
#include <memory>
#include <unistd.h>

namespace rr {

struct ReplayFlags {
  // Start a debug server for the task scheduled at the first
  // event at which reached this event AND target_process has
  // been "created".
  FrameTime goto_event;

  FrameTime singlestep_to_event;

  pid_t target_process;

  std::string target_command;

  // We let users specify which process should be "created" before
  // starting a debug session for it.  Problem is, "process" in this
  // context is ambiguous.  It could mean the "thread group", which is
  // created at fork().  Or it could mean the "address space", which is
  // created at exec() (after the fork).
  //
  // We force choosers to specify which they mean.
  enum { CREATED_NONE, CREATED_EXEC, CREATED_FORK } process_created_how;

  // Only open a debug socket, don't launch the debugger too.
  bool dont_launch_debugger;

  // IP port to listen on for debug connections.
  int dbg_port;

  // IP host to listen on for debug connections.
  std::string dbg_host;

  // Whether to keep listening with a new server after the existing server
  // detaches
  bool keep_listening;

  // Pass these options to gdb
  std::vector<std::string> gdb_options;

  // Specify a custom gdb binary with -d
  std::string gdb_binary_file_path;

  /* When true, echo tracee stdout/stderr writes to console. */
  bool redirect;

  /* When true, do not bind to the CPU stored in the trace file. */
  bool cpu_unbound;

  // When true make all private mappings shared with the tracee by default
  // to test the corresponding code.
  bool share_private_mappings;

  // When nonzero, display statistics every N steps.
  uint32_t dump_interval;

  // When set, serve files from the tracer rather than asking GDB
  // to get them from the filesystem
  bool serve_files;

  std::string tty;

  ReplayFlags()
      : goto_event(0),
        singlestep_to_event(0),
        target_process(0),
        process_created_how(CREATED_NONE),
        dont_launch_debugger(false),
        dbg_port(-1),
        dbg_host(localhost_addr),
        keep_listening(false),
        gdb_binary_file_path("gdb"),
        redirect(true),
        cpu_unbound(false),
        share_private_mappings(false),
        dump_interval(0),
        serve_files(false) {}
};
class ReplayCommand : public Command {
public:
  virtual int run(std::vector<std::string>& args) override;

  static ReplayCommand* get() { return &singleton; }


protected:
  ReplayCommand(const char* name, const char* help) : Command(name, help) {}

  static ReplayCommand singleton;
};


int start_replaying(ReplayFlags flags, std::string trace_dir);
std::unique_ptr<ReplaySession> create_replay_session(std::string trace_dir, ReplayFlags flags);
} // namespace rr

#endif // RR_REPLAY_COMMAND_H_
