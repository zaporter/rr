#pragma once

#include "GdbConnection.h"
#include <iostream>
#include <sys/types.h>

namespace rr {
class BinConnection : public GdbConnection {
  public:
    BinConnection(pid_t tgid, const Features& features) : GdbConnection(tgid, features) {
      std::cout << "HELLO I AM STANDING IN THE PLACE OF GIANTS" << std::endl;
    };
  void reply_select_thread(bool ok) override;
  void reply_get_reg(const GdbRegisterValue& value) override;
  void reply_get_regs(const std::vector<GdbRegisterValue>& file) override;
};
}
