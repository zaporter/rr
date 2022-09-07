#pragma once

#include "GdbConnection.h"
#include <iostream>
#include <sys/types.h>
#include "GdbServer.h"

#include <sys/prctl.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include <limits>
#include "ReplaySession.h"
#include "ReplayCommand.h"
#include "Session.h"

#include "Command.h"
#include "Flags.h"
#include "GdbServer.h"
#include "ReplaySession.h"
#include "core.h"
#include <memory>
#include <unistd.h>
#include <vector>
namespace rr {


/**
 * This class is a giant wrapper over the functionality provided in GdbServer. 
 * Sadly that functionality is exposed only though a message passing API so 
 * this class creates and passes message to a tricked GdbServer.
 */
class BinaryInterface  : public GdbServer {
public: 
  BinaryInterface(std::shared_ptr<ReplaySession> session, const GdbServer::Target& target)
    : GdbServer(session, target), is_processing_requests(false)
    /*GdbServer( session, target), state(REPORT_NORMAL)*/
  {


      /* GdbServer::ConnectionFlags conn_flags; */
      /* s.serve_replay(conn_flags); */
  };

  bool initialize();
  bool is_processing_requests;
  int64_t current_frame_time() const;

  // This has to be virtual in order to force the destructor to be in the library
  // Otherwise it will be optimized out by cmake. This was annoying to fix.
  virtual ~BinaryInterface() {};
  /* ReportState state; */
  /* /1* bool set_query_thread(GdbThreadId); *1/ */
  bool set_continue_thread(GdbThreadId);
  bool set_query_thread(GdbThreadId);
  GdbThreadId get_current_thread() const;
  /* std::string exec_file; */

  GdbRequest last_debugger_request_result;
  GdbRequest last_resume_request;
  ContinueOrStop continue_or_stop;
  GdbRequest process_debugger_requests(ReportState state = REPORT_NORMAL) override;
  GdbRequest placeholder_process_debugger_requests(ReportState state = REPORT_NORMAL);

  void add_pass_signal(int32_t signal);
  void clear_pass_signals();
  std::vector<GdbRegisterValue> result_get_regs;
  const std::vector<GdbRegisterValue>& get_regs() const;
  const GdbRegisterValue& get_register(GdbRegister reg_name, GdbThreadId query_thread) const;
  const std::vector<uint8_t>& file_read(const std::string& file_name, int flags, int mode);
  const std::string& get_exec_file() const;
  bool set_symbol(const std::string& name, uintptr_t address);
  
  void setfs_pid(int64_t pid);

  bool continue_forward(GdbContAction action);
  bool continue_backward(GdbContAction action);
  std::vector<GdbThreadId> get_thread_list() const;
  const std::string& get_thread_extra_info(GdbThreadId target) const;
  bool set_sw_breakpoint(uintptr_t addr, int32_t kind);
  bool remove_sw_breakpoint(uintptr_t addr, int32_t kind);
  bool set_hw_breakpoint(uintptr_t addr, int32_t kind);
  bool set_breakpoint(GdbRequestType type, uintptr_t addr, int32_t kind, std::vector<std::vector<uint8_t>> conditions);
  const std::vector<uint8_t>& get_auxv(GdbThreadId query_thread) const;
  bool has_breakpoint_at_address(GdbThreadId tuid, uintptr_t addr) const;


}; // end class
   //

std::unique_ptr<BinaryInterface> new_binary_interface_librr(int64_t,const std::string&);
void beta_test_me(); // replay
void gamma_test_me(); // ?
void delta_test_me();
/* void sayHi(); */

} // end namespace
