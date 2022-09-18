#ifndef RR_PASSTHROUGH_GDB_CONNECTION
#define RR_PASSTHROUGH_GDB_CONNECTION

#include "GdbConnection.h"
#include <cassert>
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
    val_ ## name = val; \
    consume_request(); \
  }
#define PASSTHROUGH_RAN(name) bool ran_ ## name; \
  void name () override { \
    ran_ ## name = true; \
    consume_request(); \
  }
#define PASSTHROUGH_REF(name, type, typein) type val_ ## name; \
  void name (typein val) override { \
    val_ ## name = val; \
    consume_request(); \
  }
namespace rr{

static int passthrough_to_gdb_signum(int sig) {
  switch (sig) {
    case 0:
      return 0;
    case SIGHUP:
      return 1;
    case SIGINT:
      return 2;
    case SIGQUIT:
      return 3;
    case SIGILL:
      return 4;
    case SIGTRAP:
      return 5;
    case SIGABRT /*case SIGIOT*/:
      return 6;
    case SIGBUS:
      return 10;
    case SIGFPE:
      return 8;
    case SIGKILL:
      return 9;
    case SIGUSR1:
      return 30;
    case SIGSEGV:
      return 11;
    case SIGUSR2:
      return 31;
    case SIGPIPE:
      return 13;
    case SIGALRM:
      return 14;
    case SIGTERM:
      return 15;
    /* gdb hasn't heard of SIGSTKFLT, so this is
     * arbitrarily made up.  SIGDANGER just sounds cool.*/
    case SIGSTKFLT:
      return 38 /*GDB_SIGNAL_DANGER*/;
    /*case SIGCLD*/ case SIGCHLD:
      return 20;
    case SIGCONT:
      return 19;
    case SIGSTOP:
      return 17;
    case SIGTSTP:
      return 18;
    case SIGTTIN:
      return 21;
    case SIGTTOU:
      return 22;
    case SIGURG:
      return 16;
    case SIGXCPU:
      return 24;
    case SIGXFSZ:
      return 25;
    case SIGVTALRM:
      return 26;
    case SIGPROF:
      return 27;
    case SIGWINCH:
      return 28;
    /*case SIGPOLL*/ case SIGIO:
      return 23;
    case SIGPWR:
      return 32;
    case SIGSYS:
      return 12;
    case 32:
      return 77;
    default:
      if (33 <= sig && sig <= 63) {
        /* GDB_SIGNAL_REALTIME_33 is numbered 45, hence this offset. */
        return sig + 12;
      }
      if (64 <= sig && sig <= 127) {
        /* GDB_SIGNAL_REALTIME_64 is numbered 78, hence this offset. */
        return sig + 14;
      }
      LOG(warn) << "Unknown signal " << sig;
      return 143; // GDB_SIGNAL_UNKNOWN
  }
}
class PassthroughGdbConnection : public GdbConnection {
  public: 
    PassthroughGdbConnection(pid_t tgid, const Features& features) : 
      GdbConnection(tgid, features),
      has_new_val(false)
  {
  
    multiprocess_supported_ = true;
    hwbreak_supported_ = true;
    swbreak_supported_ = true;
  };
    
    /* void reply_get_auxv(const std::vector<uint8_t>& auxv) override { */

    /* }; */
    GdbRequest val_set_req;
    bool has_new_val;

    void set_request(GdbRequest request){
      has_new_val = false;
      val_set_req = request;
    }
    bool has_exited = false;
    int exit_code = 0;
    void consume_request() override{
      has_new_val = true;
      val_set_req = GdbRequest(DREQ_NONE);

    }
    void notify_exit_code(int code) override {
      std::cout<<"EXIT"<<std::endl;
      has_exited = true;
      exit_code = code;
      consume_request();
    }
    GdbRequest get_request() override {
      return val_set_req;
    }
    void reply_setfs(int err) override {
      if (err) {
        std::cout<<"REPLY SETFS ERROR"<<std::endl;
      }
      has_new_val=true;
      consume_request();
    };
    PASSTHROUGH_RAN(notify_restart_failed);
    PASSTHROUGH_RAN(notify_restart);
    PASSTHROUGH(reply_set_mem, bool);
    PASSTHROUGH(reply_get_current_thread, GdbThreadId);
    PASSTHROUGH(reply_watchpoint_request, bool);

    bool val_reply_select_thread = false;
    void reply_select_thread (bool ok) override {
      if (ok && DREQ_SET_CONTINUE_THREAD == req.type) {
        resume_thread = req.target;
      } else if (ok && DREQ_SET_QUERY_THREAD == req.type) {
        query_thread = req.target;
      }
      val_reply_select_thread = ok;
      consume_request();

    }
    PASSTHROUGH_REF(reply_get_thread_extra_info, std::string, const std::string&); 
    PASSTHROUGH_REF(reply_get_reg, GdbRegisterValue, const GdbRegisterValue&);
    PASSTHROUGH_REF(reply_get_exec_file, std::string, const std::string&);
    PASSTHROUGH_REF(reply_get_auxv, std::vector<uint8_t>, const std::vector<uint8_t>&);
    PASSTHROUGH_REF(reply_get_mem, std::vector<uint8_t>, const std::vector<uint8_t>&);
    int val_reply_open_fd;
    int val_reply_open_err;
    void reply_open(int fd, int err) override{
      val_reply_open_fd = fd;
      val_reply_open_err = err;
      consume_request();
    }

    int val_reply_pread_err;
    std::vector<uint8_t> val_reply_pread_bytes;
    void reply_pread(const uint8_t* bytes, ssize_t len, int err) override{
      val_reply_pread_bytes.clear();
      for (int i = 0; i<len; i++){
        val_reply_pread_bytes.push_back(bytes[i]);
      }
      val_reply_pread_err = err;
      consume_request();
    }
    PASSTHROUGH(reply_close, int);


    void send_qsymbol(const std::string& name) override {
      std::cout<<"send_qsymbol "<<name  <<" called. This should NEVER be called. Please report this" << std::endl;
    };
    void qsymbols_finished() override{
      std::cout<<"qsymbols_finished called. This should NEVER be called. Please report this" << std::endl;

    };
    void add_pass_signal(int32_t signal) {
      pass_signals.insert(signal);
    }
    void clear_pass_signals(){
      pass_signals.clear();
    }
    
    int val_notify_stop_sig = 0;
    std::string val_notify_stop_reason;
    void notify_stop(GdbThreadId which, int sig, const char *reason=nullptr) override {
      //ZTODO: This needs to be fixed. It is being passed DREQ_NONE
      RUNTIME_ASSERT(req.is_resume_request() 
          || req.type == DREQ_INTERRUPT
          || req.type == DREQ_NONE);

      if (pass_signals.find(passthrough_to_gdb_signum(sig)) != pass_signals.end()) {
        /* std::cout << "discarding stop notification for signal " << sig */ 
        /*             << " on thread " << which.tid << " as specified by QPassSignal" << std::endl; */

        return;
      }
      // ZTODO: It seems to send a stop event on creation...
      if (has_new_val){
         std::cout<<"notify_stop called OVERWRITING CURRENT VAL with "<<val_notify_stop_sig<< " on "<< which.tid<<" and reason: " << val_notify_stop_reason << std::endl; 
      }
      /* RUNTIME_ASSERT(!has_new_val);// make sure we are not writing over old values */
      val_notify_stop_sig = passthrough_to_gdb_signum(sig);
      if (reason==nullptr) {
        val_notify_stop_reason = std::string();
      }else {
        val_notify_stop_reason = std::string(reason); 
      }

      consume_request();
    }
    
    bool sniff_packet() override {
      return false;
    }
    
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
