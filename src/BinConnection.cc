#include "BinConnection.h"
#include "GdbConnection.h"

namespace rr {
void BinConnection::reply_select_thread(bool ok){
  std::cout << "REPLY SELECT THREAD!! " << std::endl;
  GdbConnection::reply_select_thread(ok);
}
void BinConnection::reply_get_reg(const GdbRegisterValue& value){
  std::cout << "GET REG REPLY" << std::endl;
  GdbConnection::reply_get_reg(value);
}
void BinConnection::reply_get_regs(const std::vector<GdbRegisterValue>& file){
  std::cout << "GET REG REPLY" << std::endl;
  GdbConnection::reply_get_regs(file);

}

}
