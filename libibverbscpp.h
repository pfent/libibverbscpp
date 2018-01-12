#ifndef LIBIBVERBSCPP_LIBRARY_H
#define LIBIBVERBSCPP_LIBRARY_H

#include <infiniband/verbs.h>
#include <initializer_list>
#include <type_traits>
#include <functional>
#include <cassert>
#include <memory>

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

    namespace queuepair {
        enum class Type : std::underlying_type_t<ibv_qp_type> {
            RC = 2,
            UC,
            UD,
            RAW_PACKET = 8,
            XRC_SEND = 9,
            XRC_RECV
        };

        enum class InitAttrMask : std::underlying_type_t<ibv_qp_init_attr_mask> {
            PD = 1 << 0,
            XRCD = 1 << 1,
            CREATE_FLAGS = 1 << 2,
            RESERVED = 1 << 3
        };

        enum class CreateFlags : std::underlying_type_t<ibv_qp_create_flags> {
            BLOCK_SELF_MCAST_LB = 1 << 1,
            SCATTER_FCS = 1 << 8,
        };

        enum class OpenAttrMask : std::underlying_type_t<ibv_qp_open_attr_mask> {
            NUM = 1 << 0,
            XRCD = 1 << 1,
            CONTEXT = 1 << 2,
            TYPE = 1 << 3,
            RESERVED = 1 << 4
        };

        enum class AttrMask : std::underlying_type_t<ibv_qp_attr_mask> {
            STATE = 1 << 0,
            CUR_STATE = 1 << 1,
            EN_SQD_ASYNC_NOTIFY = 1 << 2,
            ACCESS_FLAGS = 1 << 3,
            PKEY_INDEX = 1 << 4,
            PORT = 1 << 5,
            QKEY = 1 << 6,
            AV = 1 << 7,
            PATH_MTU = 1 << 8,
            TIMEOUT = 1 << 9,
            RETRY_CNT = 1 << 10,
            RNR_RETRY = 1 << 11,
            RQ_PSN = 1 << 12,
            MAX_QP_RD_ATOMIC = 1 << 13,
            ALT_PATH = 1 << 14,
            MIN_RNR_TIMER = 1 << 15,
            SQ_PSN = 1 << 16,
            MAX_DEST_RD_ATOMIC = 1 << 17,
            PATH_MIG_STATE = 1 << 18,
            CAP = 1 << 19,
            DEST_QPN = 1 << 20
        };

        enum class State : std::underlying_type_t<ibv_qp_state> {
            RESET,
            INIT,
            RTR,
            RTS,
            SQD,
            SQE,
            ERR,
            UNKNOWN
        };

        enum class MigrationState : std::underlying_type_t<ibv_mig_state> {
            MIGRATED,
            REARM,
            ARMED
        };

        class QueuePair : ibv_qp {
            // TODO

            ~QueuePair() {
                const auto status = ::ibv_destroy_qp(this);
                assert(status == 0); // TODO: throw
            }

            int modify(ibv_qp_attr *attr, int attr_mask) {
                return ibv_modify_qp(this, attr, attr_mask);
            }

            int query(ibv_qp_attr *attr, int attr_mask, ibv_qp_init_attr *init_attr) {
                return ibv_query_qp(this, attr, attr_mask, init_attr);
            }

            int PostSend(ibv_send_wr *wr, ibv_send_wr **bad_wr) {
                return ibv_post_send(this, wr, bad_wr);
            }

            int postRecv(ibv_recv_wr *wr, ibv_recv_wr **bad_wr) {
                return ibv_post_recv(this, wr, bad_wr);
            }

            int bindMw(ibv_mw *mw, ibv_mw_bind *mw_bind) {
                return ibv_bind_mw(this, mw, mw_bind);
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

        enum class Opcode : std::underlying_type_t<ibv_wc_opcode> {
            SEND,
            RDMA_WRITE,
            RDMA_READ,
            COMP_SWAP,
            FETCH_ADD,
            BIND_MW,
            LOCAL_INV,
            RECV = 1 << 7,
            RECV_RDMA_WITH_IMM
        };

        enum class Flag : std::underlying_type_t<ibv_wc_flags> {
            GRH = 1 << 0,
            WITH_IMM = 1 << 1,
            IP_CSUM_OK = 1 << IBV_WC_IP_CSUM_OK_SHIFT,
            WITH_INV = 1 << 3
        };

        class WorkCompletion : private ibv_wc {
        public:
            uint64_t getId() const {
                return wr_id;
            }

            Status getStatus() const {
                return static_cast<Status>(status);
            }

            bool isSusccessful() const {
                return getStatus() == Status::SUCCESS;
            }

            explicit operator bool() const {
                return isSusccessful();
            }

            bool hasImmData() const {
                return testFlag(Flag::WITH_IMM);
            }

            bool hasInvRkey() const {
                return testFlag(Flag::WITH_INV);
            }

            uint32_t getImmData() const {
                assert(hasImmData());
                return imm_data;
            }

            uint32_t getInvRkey() const {
                assert(hasInvRkey());
                return imm_data;
            }

            uint32_t getQueuePairNumber() const {
                return qp_num;
            }

            uint32_t getSourceQueuePair() const {
                return src_qp;
            }

            bool testFlag(Flag flag) const {
                const auto rawFlag = static_cast<ibv_wc_flags>(flag);
                return (wc_flags & rawFlag) == rawFlag;
            }

            uint16_t getPkeyIndex() const {
                return pkey_index;
            }

            uint16_t getSlid() const {
                return slid;
            }

            uint8_t getSl() const {
                return sl;
            }

            uint8_t getDlidPathBits() const {
                return dlid_path_bits;
            };
        };
    }

    enum class NodeType : std::underlying_type_t<ibv_node_type> {
        UNKNOWN = -1,
        CA = 1,
        SWITCH,
        ROUTER,
        RNIC,
        USNIC,
        USNIC_UDP,
    };

    enum class TransportType : std::underlying_type_t<ibv_transport_type> {
        UNKNOWN = -1,
        IB = 0,
        IWARP,
        USNIC,
        USNIC_UDP,
    };

    namespace context {
        class Context;
    }

    namespace port {
        enum class State : std::underlying_type_t<ibv_port_state> {
            NOP = 0,
            DOWN = 1,
            INIT = 2,
            ARMED = 3,
            ACTIVE = 4,
            ACTIVE_DEFER = 5
        };

        enum class CapabilityFlag : std::underlying_type_t<ibv_port_cap_flags> {
            SM = 1 << 1,
            NOTICE_SUP = 1 << 2,
            TRAP_SUP = 1 << 3,
            OPT_IPD_SUP = 1 << 4,
            AUTO_MIGR_SUP = 1 << 5,
            SL_MAP_SUP = 1 << 6,
            MKEY_NVRAM = 1 << 7,
            PKEY_NVRAM = 1 << 8,
            LED_INFO_SUP = 1 << 9,
            SYS_IMAGE_GUID_SUP = 1 << 11,
            PKEY_SW_EXT_PORT_TRAP_SUP = 1 << 12,
            EXTENDED_SPEEDS_SUP = 1 << 14,
            CM_SUP = 1 << 16,
            SNMP_TUNNEL_SUP = 1 << 17,
            REINIT_SUP = 1 << 18,
            DEVICE_MGMT_SUP = 1 << 19,
            VENDOR_CLASS_SUP = 1 << 20,
            DR_NOTICE_SUP = 1 << 21,
            CAP_MASK_NOTICE_SUP = 1 << 22,
            BOOT_MGMT_SUP = 1 << 23,
            LINK_LATENCY_SUP = 1 << 24,
            CLIENT_REG_SUP = 1 << 25,
            IP_BASED_GIDS = 1 << 26
        };

        struct Attributes : ibv_port_attr {
            bool hasCapability(CapabilityFlag flag) {
                const auto rawFlag = static_cast<ibv_port_cap_flags>(flag);
                return (port_cap_flags & rawFlag) == rawFlag;
            }
        };
    }

    namespace device {
        enum class CapabilityFlag : std::underlying_type_t<ibv_device_cap_flags> {
            RESIZE_MAX_WR = 1,
            BAD_PKEY_CNTR = 1 << 1,
            BAD_QKEY_CNTR = 1 << 2,
            RAW_MULTI = 1 << 3,
            AUTO_PATH_MIG = 1 << 4,
            CHANGE_PHY_PORT = 1 << 5,
            UD_AV_PORT_ENFORCE = 1 << 6,
            CURR_QP_STATE_MOD = 1 << 7,
            SHUTDOWN_PORT = 1 << 8,
            INIT_TYPE = 1 << 9,
            PORT_ACTIVE_EVENT = 1 << 10,
            SYS_IMAGE_GUID = 1 << 11,
            RC_RNR_NAK_GEN = 1 << 12,
            SRQ_RESIZE = 1 << 13,
            N_NOTIFY_CQ = 1 << 14,
            MEM_WINDOW = 1 << 17,
            UD_IP_CSUM = 1 << 18,
            XRC = 1 << 20,
            MEM_MGT_EXTENSIONS = 1 << 21,
            MEM_WINDOW_TYPE_2A = 1 << 23,
            MEM_WINDOW_TYPE_2B = 1 << 24,
            RC_IP_CSUM = 1 << 25,
            RAW_IP_CSUM = 1 << 26,
            MANAGED_FLOW_STEERING = 1 << 29
        };

        struct Attributes : ibv_device_attr {
            bool hasCapability(CapabilityFlag flag) {
                const auto rawFlag = static_cast<ibv_device_cap_flags>(flag);
                return (device_cap_flags & rawFlag) == rawFlag;
            }
        };

        class Device : private ibv_device {
        public:
            Device() = delete;

            Device(const Device &) = delete;

            Device &operator=(Device &) = delete;

            std::string_view getName() const {
                return std::string_view(name);
            }

            std::string_view getDevName() const {
                return std::string_view(dev_name);
            }

            std::string_view getDevPath() const {
                return std::string_view(dev_path);
            }

            std::string_view getIbdevPath() const {
                return std::string_view(ibdev_path);
            }

            context::Context *open() {
                const auto context = reinterpret_cast<context::Context *>(ibv_open_device(this));
                assert(context); // TODO: throw
                return context;
            }
        };

        class DeviceList {
            Device **devices;
            int num_devices = 0;

        public:
            DeviceList() {
                devices = reinterpret_cast<Device **>(ibv_get_device_list(&num_devices));
                assert(devices); // TODO: throw error with errno
            }

            ~DeviceList() {
                ibv_free_device_list(reinterpret_cast<ibv_device **>(devices));
            }

            DeviceList(const DeviceList &) = delete;

            DeviceList &operator=(DeviceList &) = delete;

            Device **begin() {
                return devices;
            }

            Device **end() {
                return &devices[num_devices];
            }
        };
    }

    namespace context {
        class Context : private ibv_context {
        public:
            ~Context() {
                const auto status = ::ibv_close_device(this);
                assert(status == 0); // TODO: throw
            }

            device::Device *getDevice() const {
                return reinterpret_cast<device::Device *>(device);
            }

            device::Attributes getAttributes() {
                device::Attributes result;
                const auto status = ibv_query_device(this, &result);
                assert(status == 0); // TODO: throw
                return result;
            }

            port::Attributes queryPort(uint8_t port) {
                port::Attributes res;
                const auto status = ibv_query_port(this, port, &res);
                assert(status == 0); // TODO: throw
                return res;
            }
        };
    }

    namespace protectiondomain {

        class ProtectionDomain : private ibv_pd {
            friend std::unique_ptr<ProtectionDomain> make_ProtectionDomain(context::Context *);

        public:
            ProtectionDomain() = delete;

            ProtectionDomain(const ProtectionDomain &) = delete;

            ProtectionDomain &operator=(ProtectionDomain &) = delete;

            ~ProtectionDomain() {
                const auto status = ibv_dealloc_pd(this);
                assert(status != 0);
            }

            context::Context *getContext() const {
                return reinterpret_cast<context::Context *>(context);
            }

            uint32_t getHandle() const {
                return handle;
            }
        };

        std::unique_ptr<ProtectionDomain> make_ProtectionDomain(context::Context *context) {
            const auto pd = ibv_alloc_pd(reinterpret_cast<ibv_context *>(context));
            assert(pd); // TODO: throw error
            return std::unique_ptr<ProtectionDomain>(static_cast<ProtectionDomain *>(pd));
        }
    }

    namespace memorywindow {
        enum class Type : std::underlying_type_t<ibv_mw_type> {
            TYPE_1 = 1,
            TYPE_2 = 2
        };

        class BindInfo : ibv_mw_bind_info {
            // TODO
        };

        class MemoryWindow : private ibv_mw {
            friend std::unique_ptr<MemoryWindow> make_MemoryWindow(protectiondomain::ProtectionDomain *, Type);

        public:
            MemoryWindow() = delete;

            MemoryWindow(const MemoryWindow &) = delete;

            MemoryWindow &operator=(MemoryWindow &) = delete;

            ~MemoryWindow() {
                const auto status = ibv_dealloc_mw(this);
                assert(status == 0);
            }

            ibv_context *getContext() const {
                return context;
            }

            protectiondomain::ProtectionDomain *getPd() const {
                return reinterpret_cast<protectiondomain::ProtectionDomain *>(pd);
            }

            uint32_t getRkey() const {
                return rkey;
            }

            uint32_t getHandle() const {
                return handle;
            };

            Type getType() {
                return static_cast<Type>(type);
            }
        };

        std::unique_ptr<MemoryWindow> make_MemoryWindow(protectiondomain::ProtectionDomain *pd, Type type) {
            const auto mw = ibv_alloc_mw(reinterpret_cast<ibv_pd *>(pd), static_cast<ibv_mw_type>(type));
            assert(mw); // TODO: throw error
            return std::unique_ptr<MemoryWindow>(static_cast<MemoryWindow *>(mw));
        }
    }

    namespace memoryregion {
        enum class AccessFlags : std::underlying_type_t<ibv_access_flags> {
            LOCAL_WRITE = 1,
            REMOTE_WRITE = (1 << 1),
            REMOTE_READ = (1 << 2),
            REMOTE_ATOMIC = (1 << 3),
            MW_BIND = (1 << 4),
            ZERO_BASED = (1 << 5),
            ON_DEMAND = (1 << 6),
        };

        enum class ReregFlags : std::underlying_type_t<ibv_rereg_mr_flags> {
            CHANGE_TRANSLATION = (1 << 0),
            CHANGE_PD = (1 << 1),
            CHANGE_ACCESS = (1 << 2),
            KEEP_VALID = (1 << 3),
            FLAGS_SUPPORTED = ((IBV_REREG_MR_KEEP_VALID << 1) - 1)
        };

        class MemoryRegion : private ibv_mr {
        public:
            MemoryRegion() = delete;

            MemoryRegion(const MemoryRegion &) = delete;

            MemoryRegion &operator=(MemoryRegion &) = delete;

            ~MemoryRegion() {
                const auto status = ibv_dereg_mr(this);
                assert(status == 0); // TODO: log error
            }

            context::Context *getContext() const {
                return reinterpret_cast<context::Context *>(context);
            };

            protectiondomain::ProtectionDomain *getPd() const {
                return reinterpret_cast<protectiondomain::ProtectionDomain *>(pd);
            };

            void *getAddr() const {
                return addr;
            };

            size_t getLength() const {
                return length;
            };

            uint32_t getHandle() const {
                return handle;
            };

            uint32_t getLkey() const {
                return lkey;
            };

            uint32_t getRkey() const {
                return rkey;
            };
        };
    }
}

#endif