#ifndef LIBIBVERBSCPP_LIBRARY_H
#define LIBIBVERBSCPP_LIBRARY_H

#include <infiniband/verbs.h>
#include <initializer_list>
#include <type_traits>
#include <functional>
#include <cassert>
#include <memory>

namespace ibv { // TODO next: ibv_comp_channel
    class Gid {
        ibv_gid underlying;
    public:
        uint64_t getSubnetPrefix() const {
            return underlying.global.subnet_prefix;
        }

        uint64_t getInterfaceId() const {
            return underlying.global.interface_id;
        }
    };

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

        struct SendWr : private ibv_send_wr {

            void setId(uint64_t id) {
                wr_id = id;
            }

            uint64_t getId() const {
                return wr_id;
            }

            void setNext(SendWr *wrList) {
                next = wrList;
            }

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
                getWr().atomic.compare_add = value;
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

    namespace flow {
        enum class Flags : std::underlying_type_t<ibv_flow_flags> {
            ALLOW_LOOP_BACK = 1 << 0,
            DONT_TRAP = 1 << 1,
        };

        enum class AttributeType : std::underlying_type_t<ibv_flow_attr_type> {
            ORMAL = 0x0,
            LL_DEFAULT = 0x1,
            C_DEFAULT = 0x2,
        };

        enum class SpecType : std::underlying_type_t<ibv_flow_spec_type> {
            ETH = 0x20,
            IPV4 = 0x30,
            TCP = 0x40,
            UDP = 0x41,
        };

        struct Spec : private ibv_flow_spec {
            SpecType getType() const {
                return static_cast<SpecType>(hdr.type);
            }

            uint16_t getSize() const {
                return hdr.size;
            }
        };

        struct EthFilter : private ibv_flow_eth_filter {

        };

        struct IPv4Filter : private ibv_flow_ipv4_filter {

        };

        struct TcpUdpFilter : private ibv_flow_tcp_udp_filter {

        };

        struct Attributes : private ibv_flow_attr {

        };

        struct Flow : private ibv_flow {
            Flow(const Flow &) = delete; // Can't be constructed

            ~Flow() {
                const auto res = ibv_destroy_flow(this);
                assert(res == 0); // TODO: report error
            }
        };
    }

    namespace memorywindow {
        class Bind;

        class MemoryWindow;
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

        struct Attributes : private ibv_qp_attr {
            friend class QueuePair;
        };

        struct InitAttributes : private ibv_qp_init_attr {
            friend class QueuePair;
        };

        struct QueuePair : private ibv_qp {
            // TODO
            QueuePair(const QueuePair &) = delete;

            ~QueuePair() {
                const auto status = ::ibv_destroy_qp(this);
                assert(status == 0); // TODO: throw
            }

            int modify(Attributes &attr, int attr_mask) {
                return ibv_modify_qp(this, &attr, attr_mask);
            }

            int query(Attributes &attr, int attr_mask, InitAttributes &init_attr) {
                return ibv_query_qp(this, &attr, attr_mask, &init_attr);
            }

            int postSend(workrequest::SendWr &wr, ibv_send_wr *&bad_wr) {
                return ibv_post_send(this, reinterpret_cast<ibv_send_wr *>(&wr), &bad_wr);
            }

            int postRecv(workrequest::Recv &wr, ibv_recv_wr *&bad_wr) {
                return ibv_post_recv(this, reinterpret_cast<ibv_recv_wr *>(&wr), &bad_wr);
            }

            int bindMw(ibv_mw *mw, ibv_mw_bind *mw_bind) {
                return ibv_bind_mw(this, mw, mw_bind);
            }

            std::unique_ptr<flow::Flow> createFlow(flow::Attributes &attr) {
                auto res = ibv_create_flow(this, reinterpret_cast<ibv_flow_attr *>(&attr));
                assert(res != nullptr); // TODO: throw
                return std::unique_ptr<flow::Flow>(reinterpret_cast<flow::Flow *>(res));
            }

            void bindMemoryWindow(memorywindow::MemoryWindow &mw, memorywindow::Bind &info) {
                const auto status = ibv_bind_mw(this, reinterpret_cast<ibv_mw *>(&mw),
                                                reinterpret_cast<ibv_mw_bind *>(&info));
                assert(status == 0); // TODO: throw
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

    namespace event {
        enum class Type : std::underlying_type_t<ibv_event_type> {
            CQ_ERR,
            QP_FATAL,
            QP_REQ_ERR,
            QP_ACCESS_ERR,
            COMM_EST,
            SQ_DRAINED,
            PATH_MIG,
            PATH_MIG_ERR,
            DEVICE_FATAL,
            PORT_ACTIVE,
            PORT_ERR,
            LID_CHANGE,
            PKEY_CHANGE,
            SM_CHANGE,
            SRQ_ERR,
            SRQ_LIMIT_REACHED,
            QP_LAST_WQE_REACHED,
            CLIENT_REREGISTER,
            GID_CHANGE
        };

        struct AsyncEvent : private ibv_async_event {
            Type getType() const {
                return static_cast<Type>(event_type);
            }

            void ack() {
                ibv_ack_async_event(this);
            }
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

    enum class AccessFlag : std::underlying_type_t<ibv_access_flags> {
        LOCAL_WRITE = 1,
        REMOTE_WRITE = (1 << 1),
        REMOTE_READ = (1 << 2),
        REMOTE_ATOMIC = (1 << 3),
        MW_BIND = (1 << 4),
        ZERO_BASED = (1 << 5),
        ON_DEMAND = (1 << 6),
    };

    namespace context {
        class Context;
    }

    namespace protectiondomain {
        class ProtectionDomain;
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

        struct Device : private ibv_device {
            Device(const Device &) = delete;

            std::string_view getName() {
                return std::string_view(ibv_get_device_name(this));
            }

            uint64_t getGUID() {
                return ibv_get_device_guid(this);
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

    namespace memorywindow {
        enum class Type : std::underlying_type_t<ibv_mw_type> {
            TYPE_1 = 1,
            TYPE_2 = 2
        };

        class BindInfo : ibv_mw_bind_info {
            // TODO
        };

        class Bind : ibv_mw_bind {
            // TODO:
        };

        struct MemoryWindow : private ibv_mw {
            MemoryWindow(const MemoryWindow &) = delete; // Can't be constructed

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
    }

    namespace memoryregion {
        enum class ReregFlag : std::underlying_type_t<ibv_rereg_mr_flags> {
            CHANGE_TRANSLATION = (1 << 0),
            CHANGE_PD = (1 << 1),
            CHANGE_ACCESS = (1 << 2),
            KEEP_VALID = (1 << 3),
            FLAGS_SUPPORTED = ((KEEP_VALID << 1) - 1)
        };

        enum class ReregErrorCode : std::underlying_type_t<ibv_rereg_mr_err_code> {
            INPUT = -1,
            DONT_FORK_NEW = -2,
            DO_FORK_OLD = -3,
            CMD = -4,
            CMD_AND_DO_FORK_NEW = -5,
        };

        struct MemoryRegion : private ibv_mr {
            MemoryRegion(const MemoryRegion &) = delete;

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

            ReregErrorCode
            reRegister(std::initializer_list<ReregFlag> changeFlags, protectiondomain::ProtectionDomain &newPd,
                       void *newAddr,
                       size_t newLength, std::initializer_list<AccessFlag> accessFlags) {
                int changes = 0;
                for (auto change : changeFlags) {
                    changes |= static_cast<ibv_rereg_mr_flags>(change);
                }
                int access = 0;
                for (auto accessFlag : accessFlags) {
                    access |= static_cast<ibv_access_flags>(accessFlag);
                }
                const auto status = ibv_rereg_mr(this, changes,
                                                 reinterpret_cast<ibv_pd *> (&newPd), newAddr, newLength, access);
                assert(status == 0); // TODO: throw
                return static_cast<ReregErrorCode>(status);
            }
        };
    }

    namespace protectiondomain {
        struct ProtectionDomain : private ibv_pd {
            ProtectionDomain(const ProtectionDomain &) = delete;

            ~ProtectionDomain() {
                const auto status = ibv_dealloc_pd(this);
                assert(status != 0); // TODO: report error
            }

            context::Context *getContext() const {
                return reinterpret_cast<context::Context *>(context);
            }

            uint32_t getHandle() const {
                return handle;
            }

            std::unique_ptr<memoryregion::MemoryRegion>
            registerMemoryRegion(void *addr, size_t length, std::initializer_list<AccessFlag> flags) {
                int access = 0;
                for (auto flag : flags) {
                    access |= static_cast<ibv_access_flags>(flag);
                }
                auto mr = ibv_reg_mr(this, addr, length, access);
                assert(mr != nullptr); // TODO: throw
                return std::unique_ptr<memoryregion::MemoryRegion>(reinterpret_cast<memoryregion::MemoryRegion *>(mr));
            }

            std::unique_ptr<memorywindow::MemoryWindow>
            allocMemoryWindow(memorywindow::Type type) {
                const auto mw = ibv_alloc_mw(this, static_cast<ibv_mw_type>(type));
                assert(mw); // TODO: throw
                return std::unique_ptr<memorywindow::MemoryWindow>(reinterpret_cast<memorywindow::MemoryWindow *>(mw));
            }
        };
    }

    namespace xrcd {
        enum class InitAttributesMask : std::underlying_type_t<ibv_xrcd_init_attr_mask> {
            FD = 1 << 0,
            OFLAGS = 1 << 1,
            RESERVED = 1 << 2
        };

        struct InitAttributes : private ibv_xrcd_init_attr {

        };

        struct ExtendedConnectionDomain : private ibv_xrcd {
            ExtendedConnectionDomain(const ExtendedConnectionDomain &) = delete;

            ~ExtendedConnectionDomain() {
                const auto status = ibv_close_xrcd(this);
                assert(status == 0);
            }
        };
    }

    namespace context {
        struct Context : private ibv_context {

            ~Context() {
                const auto status = ::ibv_close_device(this);
                assert(status == 0); // TODO: throw
            }

            device::Device *getDevice() const {
                return reinterpret_cast<device::Device *>(device);
            }

            device::Attributes queryAttributes() {
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

            event::AsyncEvent getAsyncEvent() {
                event::AsyncEvent res{};
                const auto status = ibv_get_async_event(this, reinterpret_cast<ibv_async_event *>(&res));
                assert(status == 0); // TODO: throw
                return res;
            }

            Gid queryGid(uint8_t port_num, int index) {
                Gid res{};
                const auto status = ibv_query_gid(this, port_num, index, reinterpret_cast<ibv_gid *>(&res));
                assert(status == 0); // TODO: throw
            }

            uint16_t queryPkey(uint8_t port_num, int index) {
                uint16_t res{};
                const auto status = ibv_query_pkey(this, port_num, index, &res);
                assert(status == 0); // TODO: throw
                return res;
            }

            std::unique_ptr<protectiondomain::ProtectionDomain> allocProtectionDomain() {
                const auto pd = ibv_alloc_pd(this);
                assert(pd); // TODO: throw
                return std::unique_ptr<protectiondomain::ProtectionDomain>(
                        reinterpret_cast<protectiondomain::ProtectionDomain *>(pd));
            }

            std::unique_ptr<xrcd::ExtendedConnectionDomain> openExtendedConnectionDomain(xrcd::InitAttributes &attr) {
                const auto xrcd = ibv_open_xrcd(this, reinterpret_cast<ibv_xrcd_init_attr *>(&attr));
                assert(xrcd); // TODO: throw
                return std::unique_ptr<xrcd::ExtendedConnectionDomain>(
                        reinterpret_cast<xrcd::ExtendedConnectionDomain *>(xrcd));
            }

            void createCompletionEventChannel() {
                const auto compChannel = ibv_create_comp_channel(this);
                assert(compChannel != nullptr);
                //return compChannel;
            }
        };
    }

    uint32_t incRkey(uint32_t rkey) {
        return ibv_inc_rkey(rkey);
    }
}

#endif