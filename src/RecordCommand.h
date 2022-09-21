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
//int start_recording(vector<string>& args, RecordFlags& flags);

class RecordCommand : public Command {
public:
  virtual int run(std::vector<std::string>& args) override;

  static RecordCommand* get() { return &singleton; }

protected:
  RecordCommand(const char* name, const char* help) : Command(name, help) {}

  static RecordCommand singleton;
};

class RecordingInterface {
  public:

    RecordSession::RecordResult step_result;
    std::shared_ptr<rr::RecordSession> session;
    bool did_forward_SIGTERM;
    bool did_term_detached_tasks;
    pthread_t term_repeater_thread;
    std::string output_trace_dir;
    RecordingInterface(std::shared_ptr<rr::RecordSession> session, std::string output_trace_dir);

    bool continue_recording();

  int64_t current_frame_time() const;
  // This has to be virtual in order to force the destructor to be in the library
  // Otherwise it will be optimized out by cmake. This was annoying to fix.
  virtual ~RecordingInterface() {};

};

std::unique_ptr<RecordingInterface> new_recording_interface(const std::string&);

} // namespace rr

#endif // RR_RECORD_COMMAND_H_
