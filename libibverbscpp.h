#ifndef LIBIBVERBSCPP_LIBRARY_H
#define LIBIBVERBSCPP_LIBRARY_H

#include <infiniband/verbs.h>
#include <initializer_list>
#include <type_traits>
#include <functional>

namespace ibv {
    namespace workrequest {
        // internal
        enum class Opcode : std::underlying_type_t<ibv_wr_opcode> {
            RDMA_WRITE,
            RDMA_WRITE_WITH_IMM,
            SEND,
            SEND_WITH_IMM,
            RDMA_READ,
            ATOMIC_CMP_AND_SWP,
            ATOMIC_FETCH_AND_ADD,
            LOCAL_INV,
            BIND_MW,
            SEND_WITH_INV,
        };

        enum class Flags : std::underlying_type_t<ibv_send_flags> {
            FENCE = 1 << 0,
            SIGNALED = 1 << 1,
            SOLICITED = 1 << 2,
            INLINE = 1 << 3,
            IP_CSUM = 1 << 4
        };

        // internal
        struct SendWr : private ibv_send_wr {
        public:
            void setId(uint64_t id) {
                wr_id = id;
            }

            uint64_t getId() const {
                return wr_id;
            }

            void setNext(SendWr *wrList) {
                next = wrList;
            }

        public:
            void setSge(ibv_sge *sg_list, int num_sge) { // TODO: setLocalAddress instead of SGE
                this->sg_list = sg_list;
                this->num_sge = num_sge;
            }

        protected:
            void setOpcode(Opcode opcode) {
                this->opcode = static_cast<ibv_wr_opcode>(opcode);
            }

        public:
            void setFlags(std::initializer_list<Flags> flags) { // TODO: utility functions with bools
                send_flags = 0;
                for (const auto flag : flags) {
                    send_flags |= static_cast<ibv_send_flags>(flag);
                }
            }

        protected:
            void setImmData(uint32_t data) {
                imm_data = data;
            }

            decltype(wr) &getWr() {
                return wr;
            }
        };

        // internal
        struct Rdma : SendWr {
            void setRemoteAddress(uint64_t remote_addr, uint32_t rkey) { // TODO: structure for this
                getWr().rdma.remote_addr = remote_addr;
                getWr().rdma.rkey = rkey;
            };
        };

        struct Write : Rdma {
        public:
            Write() : Rdma{} {
                SendWr::setOpcode(Opcode::RDMA_WRITE);
            }
        };

        struct WriteWithImm : Write {
        public:
            WriteWithImm() : Write{} {
                WriteWithImm::setOpcode(Opcode::RDMA_WRITE_WITH_IMM);
            }

            using SendWr::setImmData;
        };

        struct Send : SendWr {
        public:
            Send() : SendWr{} {
                SendWr::setOpcode(Opcode::SEND);
            }
        };

        struct SendWithImm : SendWr {
        public:
            SendWithImm() : SendWr{} {
                SendWr::setOpcode(Opcode::SEND_WITH_IMM);
            }

            using SendWr::setImmData;
        };

        struct Read : Rdma {
            Read() : Rdma{} {
                SendWr::setOpcode(Opcode::RDMA_READ);
            }
        };

        // internal
        struct Atomic : SendWr {
            void setRemoteAddress(uint64_t remote_addr, uint32_t rkey) { // TODO: structure for this
                getWr().atomic.remote_addr = remote_addr;
                getWr().atomic.rkey = rkey;
            };
        };

        struct AtomicCompareSwap : Atomic {
            AtomicCompareSwap() : Atomic{} {
                SendWr::setOpcode(Opcode::ATOMIC_CMP_AND_SWP);
            }

            AtomicCompareSwap(uint64_t compare, uint64_t swap) : AtomicCompareSwap() {
                setCompareValue(compare);
                setSwapValue(swap);
            }

            void setCompareValue(uint64_t value) {
                getWr().atomic.compare_add = value;
            }

            void setSwapValue(uint64_t value) {
                getWr().atomic.swap = value;
            }
        };

        struct AtomicFetchAdd : Atomic {
            AtomicFetchAdd() : Atomic{} {
                SendWr::setOpcode(Opcode::ATOMIC_FETCH_AND_ADD);
            }

            explicit AtomicFetchAdd(uint64_t value) : AtomicFetchAdd() {
                setAddValue(value);
            }

            void setAddValue(uint64_t value) {
                getWr().atomic.compare_add;
            }
        };

        struct Recv : private ibv_recv_wr {
            void setId(uint64_t id) {
                wr_id = id;
            }

            uint64_t getId() const {
                return wr_id;
            }

            void setNext(Recv *next) {
                this->next = next;
            }

            void setSge(ibv_sge *sg_list, int num_sge) { // TODO: setLocalAddress instead of SGE
                this->sg_list = sg_list;
                this->num_sge = num_sge;
            }
        };

        template<class SendWorkRequest>
        class Simple : public SendWorkRequest {
            static_assert(std::is_base_of<ibv_send_wr, SendWorkRequest>::value);

            ibv_sge sge{};

        public:
            using SendWorkRequest::SendWorkRequest;

            void setLocalAddress(uint64_t addr, uint32_t length, uint32_t lkey) {
                this->sg_list = &sge;
                this->num_sge = 1;

                sge.addr = addr;
                sge.length = length;
                sge.lkey = lkey;
            }
        };
    }

    namespace workcompletion {
        enum class Status : std::underlying_type_t<ibv_wc_status> {
            SUCCESS,
            LOC_LEN_ERR,
            LOC_QP_OP_ERR,
            LOC_EEC_OP_ERR,
            LOC_PROT_ERR,
            WR_FLUSH_ERR,
            MW_BIND_ERR,
            BAD_RESP_ERR,
            LOC_ACCESS_ERR,
            REM_INV_REQ_ERR,
            REM_ACCESS_ERR,
            REM_OP_ERR,
            RETRY_EXC_ERR,
            RNR_RETRY_EXC_ERR,
            LOC_RDD_VIOL_ERR,
            REM_INV_RD_REQ_ERR,
            REM_ABORT_ERR,
            INV_EECN_ERR,
            INV_EEC_STATE_ERR,
            FATAL_ERR,
            RESP_TIMEOUT_ERR,
            GENERAL_ERR
        };
    }
}

#endif