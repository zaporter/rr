#ifndef RR_PASSTHROUGH_GDB_CONNECTION
#define RR_PASSTHROUGH_GDB_CONNECTION

#include "GdbConnection.h"
#include <vector>

/* This function generates a version of from the input*/

/* GdbThreadId val_reply_get_current_thread; */
/* void reply_get_current_thread(GdbThreadId thread) override { */
/*   has_new_val = true; */
/*   val_reply_get_current_thread = thread; */
/* } */
#define PASSTHROUGH(name, type) type val_ ## name; \
  void name (type val) override { \
    has_new_val = true; \
    val_ ## name = val; \
  }
namespace rr{

class PassthroughGdbConnection : public GdbConnection {
  public: 
    PassthroughGdbConnection(pid_t tgid, const Features& features) : 
      GdbConnection(tgid, features),
      has_new_val(false)
  {};
    
    /* void reply_get_auxv(const std::vector<uint8_t>& auxv) override { */

    /* }; */
    GdbRequest val_set_req;
    bool has_new_val;

    void set_request(GdbRequest request){
      val_set_req = request;
    }
    GdbRequest get_request() override {
      return val_set_req;
    }
    PASSTHROUGH(reply_get_current_thread, GdbThreadId);
    std::vector<uint8_t> val_reply_get_auxv;
    void reply_get_auxv(const std::vector<uint8_t>& val) override {
        val_reply_get_auxv = std::vector<uint8_t>(val);
    };
    //PASSTHROUGH(reply_get_auxv, const std::vector<uint8_t>&);

};

} // namespace rr
#endif /*RR_PASSTHROUGH_GDB_CONNECTION*/
