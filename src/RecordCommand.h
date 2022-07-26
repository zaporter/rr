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

} // namespace rr

#endif // RR_RECORD_COMMAND_H_
