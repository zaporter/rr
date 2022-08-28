#ifndef RR_PASSTHROUGH_GDB_CONNECTION
#define RR_PASSTHROUGH_GDB_CONNECTION

#include "GdbConnection.h"
#include <iostream>
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
#define PASSTHROUGH_REF(name, type, typein) type val_ ## name; \
  void name (typein val) override { \
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
    void reply_setfs(int err) override {
        std::cout<<"SETFS"<<std::endl;
      if (err) {
        std::cout<<"ERROR"<<std::endl;
      }
      has_new_val=true;
    };
    PASSTHROUGH(reply_get_current_thread, GdbThreadId);
    PASSTHROUGH(reply_watchpoint_request, bool);
    PASSTHROUGH_REF(reply_get_thread_extra_info, std::string, const std::string&); 
    PASSTHROUGH_REF(reply_get_reg, GdbRegisterValue, const GdbRegisterValue&);
    PASSTHROUGH_REF(reply_get_auxv, std::vector<uint8_t>, const std::vector<uint8_t>&);

    int val_reply_open_fd;
    int val_reply_open_err;
    void reply_open(int fd, int err) override{
      val_reply_open_fd = fd;
      val_reply_open_err = err;
    }
    int val_reply_pread_err;
    std::vector<uint8_t> val_reply_pread_bytes;
    void reply_pread(const uint8_t* bytes, ssize_t len, int err) override{
      val_reply_pread_bytes.clear();
      for (int i = 0; i<len; i++){
        val_reply_pread_bytes.push_back(bytes[i]);
      }
      val_reply_pread_err = err;
    }
    PASSTHROUGH(reply_close, int);
    /* void reply_close(int err) override{ */
    /*   DEBUG_ASSERT(DREQ_FILE_CLOSE == req.type); */
    /*   if (err) { */
    /*     send_file_error_reply(err); */
    /*   } else { */
    /*     write_packet("F0"); */
    /* } */

    /* std::vector<uint8_t> val_reply_get_auxv; */
    /* void reply_get_auxv(const std::vector<uint8_t>& val) override { */
    /*     val_reply_get_auxv = std::vector<uint8_t>(val); */
    /* }; */
    
    //PASSTHROUGH(reply_get_auxv, const std::vector<uint8_t>&);

};

} // namespace rr
#endif /*RR_PASSTHROUGH_GDB_CONNECTION*/
