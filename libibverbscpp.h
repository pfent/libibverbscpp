#ifndef LIBIBVERBSCPP_LIBRARY_H
#define LIBIBVERBSCPP_LIBRARY_H

#include <fcntl.h>
#include <infiniband/verbs.h>
#include <iostream>
#include <memory>
#include <sstream>

namespace ibv {
    namespace internal {
        [[nodiscard]]
        inline std::runtime_error exception(const char *function, int errnum) {
            return std::runtime_error(
                    std::string(function) + " failed with error " + std::to_string(errnum) + ": " + strerror(errnum));
        }

        constexpr void check(const char *function, bool ok) {
            if (not ok) {
                throw exception(function, errno);
            }
        }

        constexpr void checkStatus(const char *function, int status) {
            if (status != 0) {
                throw exception(function, status);
            }
        }

        constexpr void checkPtr(const char *function, const void *ptr) {
            if (ptr == nullptr) {
                throw exception(function, errno);
            }
        }

        constexpr void checkStatusNoThrow(const char *function, int status) noexcept {
            if (status != 0) {
                std::clog << function << " failed with error " << std::to_string(status) << ": " << strerror(status);
            }
        }

        struct PointerOnly {
            PointerOnly() = delete;

            PointerOnly(const PointerOnly &) = delete;

            PointerOnly &operator=(const PointerOnly &) = delete;

            PointerOnly(PointerOnly &&) = delete;

            PointerOnly &operator=(PointerOnly &&) = delete;

            ~PointerOnly() = default;
        };
    } // namespace internal

    enum class NodeType : std::underlying_type_t<ibv_node_type> {
        UNKNOWN = IBV_NODE_UNKNOWN,
        CA = IBV_NODE_CA,
        SWITCH = IBV_NODE_SWITCH,
        ROUTER = IBV_NODE_ROUTER,
        RNIC = IBV_NODE_RNIC,
        USNIC = IBV_NODE_USNIC,
        USNIC_UDP = IBV_NODE_USNIC_UDP
    };

    enum class TransportType : std::underlying_type_t<ibv_transport_type> {
        UNKNOWN = IBV_TRANSPORT_UNKNOWN,
        IB = IBV_TRANSPORT_IB,
        IWARP = IBV_TRANSPORT_IWARP,
        USNIC = IBV_TRANSPORT_USNIC,
        USNIC_UDP = IBV_TRANSPORT_USNIC_UDP
    };

    enum class AccessFlag : std::underlying_type_t<ibv_access_flags> {
        LOCAL_WRITE = IBV_ACCESS_LOCAL_WRITE,
        REMOTE_WRITE = IBV_ACCESS_REMOTE_WRITE, /// Enable Remote Write Access. Requires local write access to the MR
        REMOTE_READ = IBV_ACCESS_REMOTE_READ, /// Enable Remote Read Access
        REMOTE_ATOMIC = IBV_ACCESS_REMOTE_ATOMIC, /// Enable Remote Atomic Operation Access (if supported). Requires local write access to the MR
        MW_BIND = IBV_ACCESS_MW_BIND,
        ZERO_BASED = IBV_ACCESS_ZERO_BASED, /// If set, the address set on the 'remote_addr' field on the WR will be an offset from the MW's start address.
        ON_DEMAND = IBV_ACCESS_ON_DEMAND
    };

    struct Gid {
        ibv_gid underlying;

        [[nodiscard]]
        constexpr uint64_t getSubnetPrefix() const {
            return underlying.global.subnet_prefix;
        }

        [[nodiscard]]
        constexpr uint64_t getInterfaceId() const {
            return underlying.global.interface_id;
        }
    };

    class GlobalRoutingHeader : public ibv_grh {
        using ibv_grh::version_tclass_flow;
        using ibv_grh::paylen;
        using ibv_grh::next_hdr;
        using ibv_grh::hop_limit;
        using ibv_grh::sgid;
        using ibv_grh::dgid;
    public:
        [[nodiscard]]
        constexpr uint32_t getVersionTclassFlow() const {
            return version_tclass_flow;
        }

        [[nodiscard]]
        constexpr uint16_t getPaylen() const {
            return paylen;
        }

        [[nodiscard]]
        constexpr uint8_t getNextHdr() const {
            return next_hdr;
        }

        [[nodiscard]]
        constexpr uint8_t getHopLimit() const {
            return hop_limit;
        }

        [[nodiscard]]
        const Gid &getSgid() const {
            return *reinterpret_cast<const Gid *>(&sgid);
        }

        [[nodiscard]]
        const Gid &getDgid() const {
            return *reinterpret_cast<const Gid *>(&dgid);
        }
    };

    static_assert(sizeof(GlobalRoutingHeader) == sizeof(ibv_grh));

    class GlobalRoute : public ibv_global_route {
        using ibv_global_route::dgid;
        using ibv_global_route::flow_label;
        using ibv_global_route::sgid_index;
        using ibv_global_route::hop_limit;
        using ibv_global_route::traffic_class;
    public:
        /// Destination GID or MGID
        [[nodiscard]]
        const Gid &getDgid() const {
            return *reinterpret_cast<const Gid *>(&dgid);
        }

        /// Flow label
        [[nodiscard]]
        uint32_t getFlowLabel() const {
            return flow_label;
        }

        /// Source GID index
        [[nodiscard]]
        uint8_t getSgidIndex() const {
            return sgid_index;
        }

        /// Hop limit
        [[nodiscard]]
        uint8_t getHopLimit() const {
            return hop_limit;
        }

        /// Traffic class
        [[nodiscard]]
        uint8_t getTrafficClass() const {
            return traffic_class;
        }
    };

    static_assert(sizeof(GlobalRoute) == sizeof(ibv_global_route));

    namespace flow {
        enum class Flags : std::underlying_type_t<ibv_flow_flags> {
            ALLOW_LOOP_BACK = IBV_FLOW_ATTR_FLAGS_ALLOW_LOOP_BACK,
            DONT_TRAP = IBV_FLOW_ATTR_FLAGS_DONT_TRAP
        };

        enum class AttributeType : std::underlying_type_t<ibv_flow_attr_type> {
            NORMAL = IBV_FLOW_ATTR_NORMAL,
            ALL_DEFAULT = IBV_FLOW_ATTR_ALL_DEFAULT,
            MC_DEFAULT = IBV_FLOW_ATTR_MC_DEFAULT
        };

        enum class SpecType : std::underlying_type_t<ibv_flow_spec_type> {
            ETH = IBV_FLOW_SPEC_ETH,
            IPV4 = IBV_FLOW_SPEC_IPV4,
            TCP = IBV_FLOW_SPEC_TCP,
            UDP = IBV_FLOW_SPEC_UDP
        };

        struct Spec : ibv_flow_spec {
            constexpr SpecType getType() const {
                return static_cast<SpecType>(hdr.type);
            }

            constexpr uint16_t getSize() const {
                return hdr.size;
            }
        };

        struct EthFilter : ibv_flow_eth_filter {
        };

        struct IPv4Filter : ibv_flow_ipv4_filter {
        };

        struct TcpUdpFilter : ibv_flow_tcp_udp_filter {
        };

        struct Attributes : ibv_flow_attr {
        };

        class Flow : public ibv_flow, public internal::PointerOnly {
            using ibv_flow::comp_mask;
            using ibv_flow::context;
            using ibv_flow::handle;

        public:
            static void *operator new(std::size_t) noexcept = delete;

            static void operator delete(void *ptr) noexcept {
                const auto status = ibv_destroy_flow(reinterpret_cast<ibv_flow *>(ptr));
                internal::checkStatusNoThrow("ibv_destroy_flow", status);
            }
        };
    } // namespace flow

    namespace context {
        struct Context;
    } // namespace context

    namespace protectiondomain {
        struct ProtectionDomain;
    } // namespace protectiondomain

    namespace queuepair {
        struct Attributes;
    } // namespace queuepair

    namespace memoryregion {
        struct MemoryRegion;
    } // namespace memoryregion

    namespace workcompletion {
        enum class Status : std::underlying_type_t<ibv_wc_status> {
            SUCCESS = IBV_WC_SUCCESS,
            LOC_LEN_ERR = IBV_WC_LOC_LEN_ERR,
            LOC_QP_OP_ERR = IBV_WC_LOC_QP_OP_ERR,
            LOC_EEC_OP_ERR = IBV_WC_LOC_EEC_OP_ERR,
            LOC_PROT_ERR = IBV_WC_LOC_PROT_ERR,
            WR_FLUSH_ERR = IBV_WC_WR_FLUSH_ERR,
            MW_BIND_ERR = IBV_WC_MW_BIND_ERR,
            BAD_RESP_ERR = IBV_WC_BAD_RESP_ERR,
            LOC_ACCESS_ERR = IBV_WC_LOC_ACCESS_ERR,
            REM_INV_REQ_ERR = IBV_WC_REM_INV_REQ_ERR,
            REM_ACCESS_ERR = IBV_WC_REM_ACCESS_ERR,
            REM_OP_ERR = IBV_WC_REM_OP_ERR,
            RETRY_EXC_ERR = IBV_WC_RETRY_EXC_ERR,
            RNR_RETRY_EXC_ERR = IBV_WC_RNR_RETRY_EXC_ERR,
            LOC_RDD_VIOL_ERR = IBV_WC_LOC_RDD_VIOL_ERR,
            REM_INV_RD_REQ_ERR = IBV_WC_REM_INV_RD_REQ_ERR,
            REM_ABORT_ERR = IBV_WC_REM_ABORT_ERR,
            INV_EECN_ERR = IBV_WC_INV_EECN_ERR,
            INV_EEC_STATE_ERR = IBV_WC_INV_EEC_STATE_ERR,
            FATAL_ERR = IBV_WC_FATAL_ERR,
            RESP_TIMEOUT_ERR = IBV_WC_RESP_TIMEOUT_ERR,
            GENERAL_ERR = IBV_WC_GENERAL_ERR
        };

        enum class Opcode : std::underlying_type_t<ibv_wc_opcode> {
            SEND = IBV_WC_SEND,
            RDMA_WRITE = IBV_WC_RDMA_WRITE,
            RDMA_READ = IBV_WC_RDMA_READ,
            COMP_SWAP = IBV_WC_COMP_SWAP,
            FETCH_ADD = IBV_WC_FETCH_ADD,
            BIND_MW = IBV_WC_BIND_MW,
            LOCAL_INV = IBV_WC_LOCAL_INV,
            RECV = IBV_WC_RECV,
            RECV_RDMA_WITH_IMM = IBV_WC_RECV_RDMA_WITH_IMM
        };

        enum class Flag : std::underlying_type_t<ibv_wc_flags> {
            GRH = IBV_WC_GRH,
            WITH_IMM = IBV_WC_WITH_IMM,
            IP_CSUM_OK = IBV_WC_IP_CSUM_OK,
            WITH_INV = IBV_WC_WITH_INV
        };

        class WorkCompletion : public ibv_wc {
            using ibv_wc::wr_id;
            using ibv_wc::status;
            using ibv_wc::opcode;
            using ibv_wc::vendor_err;
            using ibv_wc::byte_len;
            using ibv_wc::imm_data;
            using ibv_wc::invalidated_rkey;
            using ibv_wc::qp_num;
            using ibv_wc::src_qp;
            using ibv_wc::wc_flags;
            using ibv_wc::pkey_index;
            using ibv_wc::slid;
            using ibv_wc::sl;
            using ibv_wc::dlid_path_bits;
        public:
            [[nodiscard]]
            constexpr uint64_t getId() const {
                return wr_id;
            }

            [[nodiscard]]
            constexpr Status getStatus() const {
                return static_cast<Status>(status);
            }

            [[nodiscard]]
            constexpr bool isSuccessful() const {
                return getStatus() == Status::SUCCESS;
            }

            [[nodiscard]]
            explicit constexpr operator bool() const {
                return isSuccessful();
            }

            [[nodiscard]]
            constexpr Opcode getOpcode() const {
                return static_cast<Opcode>(opcode);
            }

            [[nodiscard]]
            constexpr bool hasImmData() const {
                return testFlag(Flag::WITH_IMM);
            }

            [[nodiscard]]
            constexpr bool hasInvRkey() const {
                return testFlag(Flag::WITH_INV);
            }

            [[nodiscard]]
            constexpr uint32_t getImmData() const {
                checkCondition(hasImmData());
                return imm_data;
            }

            [[nodiscard]]
            constexpr uint32_t getInvRkey() const {
                checkCondition(hasInvRkey());
                return imm_data;
            }

            [[nodiscard]]
            constexpr uint32_t getQueuePairNumber() const {
                return qp_num;
            }

            [[nodiscard]]
            constexpr uint32_t getSourceQueuePair() const {
                return src_qp;
            }

            [[nodiscard]]
            constexpr bool testFlag(Flag flag) const {
                const auto rawFlag = static_cast<ibv_wc_flags>(flag);
                return (wc_flags & rawFlag) == rawFlag;
            }

            [[nodiscard]]
            constexpr uint16_t getPkeyIndex() const {
                return pkey_index;
            }

            [[nodiscard]]
            constexpr uint16_t getSlid() const {
                return slid;
            }

            [[nodiscard]]
            constexpr uint8_t getSl() const {
                return sl;
            }

            [[nodiscard]]
            constexpr uint8_t getDlidPathBits() const {
                return dlid_path_bits;
            }

        private:
            constexpr static void checkCondition(bool condition) {
                if (not condition) {
                    throw std::logic_error("Invalid workcompletion data access");
                }
            }
        };

        static_assert(sizeof(WorkCompletion) == sizeof(ibv_wc));

        [[nodiscard]]
        inline std::string to_string(Opcode opcode) {
            switch (opcode) {
                case Opcode::SEND:
                    return "IBV_WC_SEND";
                case Opcode::RDMA_WRITE:
                    return "IBV_WC_RDMA_WRITE";
                case Opcode::RDMA_READ:
                    return "IBV_WC_RDMA_READ";
                case Opcode::COMP_SWAP:
                    return "IBV_WC_COMP_SWAP";
                case Opcode::FETCH_ADD:
                    return "IBV_WC_FETCH_ADD";
                case Opcode::BIND_MW:
                    return "IBV_WC_BIND_MW";
                case Opcode::LOCAL_INV:
                    return "IBV_WC_LOCAL_INV";
                case Opcode::RECV:
                    return "IBV_WC_RECV";
                case Opcode::RECV_RDMA_WITH_IMM:
                    return "IBV_WC_RECV_RDMA_WITH_IMM";
            }
            __builtin_unreachable();
        }

        [[nodiscard]]
        inline std::string to_string(Status status) {
            return ibv_wc_status_str(static_cast<ibv_wc_status>(status));
        }
    } // namespace workcompletion

    namespace ah {
        class Attributes : public ibv_ah_attr {
            using ibv_ah_attr::grh;
            using ibv_ah_attr::dlid;
            using ibv_ah_attr::sl;
            using ibv_ah_attr::src_path_bits;
            using ibv_ah_attr::static_rate;
            using ibv_ah_attr::is_global;
            using ibv_ah_attr::port_num;
        public:
            /// Global Routing Header (GRH) attributes
            [[nodiscard]]
            const GlobalRoute &getGrh() const {
                return *reinterpret_cast<const GlobalRoute *>(&grh);
            }

            /// Global Routing Header (GRH) attributes
            constexpr void setGrh(const GlobalRoute &grh) {
                this->grh = grh;
            }

            /// Destination LID
            [[nodiscard]]
            constexpr uint16_t getDlid() const {
                return dlid;
            }

            /// Destination LID
            constexpr void setDlid(uint16_t dlid) {
                this->dlid = dlid;
            }

            /// Service Level
            [[nodiscard]]
            constexpr uint8_t getSl() const {
                return sl;
            }

            /// Service Level
            constexpr void setSl(uint8_t sl) {
                this->sl = sl;
            }

            /// Source path bits
            [[nodiscard]]
            constexpr uint8_t getSrcPathBits() const {
                return src_path_bits;
            }

            /// Source path bits
            constexpr void setSrcPathBits(uint8_t src_path_bits) {
                this->src_path_bits = src_path_bits;
            }

            /// Maximum static rate
            [[nodiscard]]
            constexpr uint8_t getStaticRate() const {
                return static_rate;
            }

            /// Maximum static rate
            constexpr void setStaticRate(uint8_t static_rate) {
                this->static_rate = static_rate;
            }

            /// GRH attributes are valid
            [[nodiscard]]
            constexpr bool getIsGlobal() const {
                return static_cast<bool>(is_global);
            }

            /// GRH attributes are valid
            constexpr void setIsGlobal(bool is_global) {
                this->is_global = static_cast<uint8_t>(is_global);
            }

            /// Physical port number
            [[nodiscard]]
            constexpr uint8_t getPortNum() const {
                return port_num;
            }

            /// Physical port number
            constexpr void setPortNum(uint8_t port_num) {
                this->port_num = port_num;
            }
        };

        static_assert(sizeof(Attributes) == sizeof(ibv_ah_attr));

        class AddressHandle : public ibv_ah, public internal::PointerOnly {
            using ibv_ah::context;
            using ibv_ah::pd;
            using ibv_ah::handle;
        public:
            static void *operator new(std::size_t) noexcept = delete;

            static void operator delete(void *ptr) noexcept {
                const auto status = ibv_destroy_ah(reinterpret_cast<ibv_ah *>(ptr));
                internal::checkStatusNoThrow("ibv_destroy_ah", status);
            }
        };

        static_assert(sizeof(AddressHandle) == sizeof(ibv_ah));
    } // namespace ah

    namespace completions {
        class CompletionQueue : public ibv_cq, public internal::PointerOnly {
            using ibv_cq::context;
            using ibv_cq::channel;
            using ibv_cq::cq_context;
            using ibv_cq::handle;
            using ibv_cq::cqe;
            using ibv_cq::mutex;
            using ibv_cq::cond;
            using ibv_cq::comp_events_completed;
            using ibv_cq::async_events_completed;
        public:
            static void *operator new(std::size_t) noexcept = delete;

            static void operator delete(void *ptr) noexcept {
                const auto status = ibv_destroy_cq(reinterpret_cast<ibv_cq *>(ptr));
                internal::checkStatusNoThrow("ibv_destroy_cq", status);
            }

            /// Resize the CompletionQueue to have at last newCqe entries
            void resize(int newCqe) {
                const auto status = ibv_resize_cq(this, newCqe);
                internal::checkStatus("ibv_resize_cq", status);
            }

            /// Acknowledge nEvents events on the CompletionQueue
            void ackEvents(unsigned int nEvents) {
                ibv_ack_cq_events(this, nEvents);
            }

            /// Poll the CompletionQueue for the next numEntries WorkCompletions and put them into resultArray
            /// @returns the number of completions found
            [[nodiscard]]
            int poll(int numEntries, workcompletion::WorkCompletion *resultArray) {
                const auto res = ibv_poll_cq(this, numEntries, resultArray);
                internal::check("ibv_poll_cq", res >= 0);
                return res;
            }

            /// Request completion notification event on this CompletionQueue for the associated CompletionEventChannel
            /// @param solicitedOnly if the events should only be produced for workrequests with Flags::SOLICITED
            void requestNotify(bool solicitedOnly) {
                const auto status = ibv_req_notify_cq(this, static_cast<int>(solicitedOnly));
                internal::checkStatus("ibv_req_notify_cq", status);
            }
        };

        static_assert(sizeof(CompletionQueue) == sizeof(ibv_cq));

        class CompletionEventChannel : public ibv_comp_channel, public internal::PointerOnly {
            using ibv_comp_channel::context;
            using ibv_comp_channel::fd;
            using ibv_comp_channel::refcnt;
        public:
            static void *operator new(std::size_t) noexcept = delete;

            static void operator delete(void *ptr) noexcept {
                const auto status = ibv_destroy_comp_channel(reinterpret_cast<ibv_comp_channel *>(ptr));
                internal::checkStatusNoThrow("ibv_destroy_comp_channel", status);
            }

            /// Wait for the next completion event in this CompletionEventChannel
            /// @returns the CompletionQueue, that got the event and the CompletionQueues QP context @see setQpContext
            [[nodiscard]]
            std::tuple<CompletionQueue *, void *> getEvent() {
                CompletionQueue *cqRet;
                void *contextRet;
                const auto status = ibv_get_cq_event(this, reinterpret_cast<ibv_cq **>(&cqRet), &contextRet);
                internal::checkStatus("ibv_get_cq_event", status);
                return {cqRet, contextRet};
            }
        };

        static_assert(sizeof(CompletionEventChannel) == sizeof(ibv_comp_channel));
    } // namespace completions

    enum class Mtu : std::underlying_type_t<ibv_mtu> {
        _256 = IBV_MTU_256,
        _512 = IBV_MTU_512,
        _1024 = IBV_MTU_1024,
        _2048 = IBV_MTU_2048,
        _4096 = IBV_MTU_4096
    };

    [[nodiscard]]
    inline std::string to_string(Mtu mtu) {
        switch (mtu) {
            case Mtu::_256:
                return "IBV_MTU_256";
            case Mtu::_512:
                return "IBV_MTU_512";
            case Mtu::_1024:
                return "IBV_MTU_1024";
            case Mtu::_2048:
                return "IBV_MTU_2048";
            case Mtu::_4096:
                return "IBV_MTU_4096";
        }
        __builtin_unreachable();
    }

    namespace port {
        enum class State : std::underlying_type_t<ibv_port_state> {
            NOP = IBV_PORT_NOP,
            DOWN = IBV_PORT_DOWN,
            INIT = IBV_PORT_INIT,
            ARMED = IBV_PORT_ARMED,
            ACTIVE = IBV_PORT_ACTIVE,
            ACTIVE_DEFER = IBV_PORT_ACTIVE_DEFER
        };

        enum class CapabilityFlag : std::underlying_type_t<ibv_port_cap_flags> {
            SM = IBV_PORT_SM,
            NOTICE_SUP = IBV_PORT_NOTICE_SUP,
            TRAP_SUP = IBV_PORT_TRAP_SUP,
            OPT_IPD_SUP = IBV_PORT_OPT_IPD_SUP,
            AUTO_MIGR_SUP = IBV_PORT_AUTO_MIGR_SUP,
            SL_MAP_SUP = IBV_PORT_SL_MAP_SUP,
            MKEY_NVRAM = IBV_PORT_MKEY_NVRAM,
            PKEY_NVRAM = IBV_PORT_PKEY_NVRAM,
            LED_INFO_SUP = IBV_PORT_LED_INFO_SUP,
            SYS_IMAGE_GUID_SUP = IBV_PORT_SYS_IMAGE_GUID_SUP,
            PKEY_SW_EXT_PORT_TRAP_SUP = IBV_PORT_PKEY_SW_EXT_PORT_TRAP_SUP,
            EXTENDED_SPEEDS_SUP = IBV_PORT_EXTENDED_SPEEDS_SUP,
            CM_SUP = IBV_PORT_CM_SUP,
            SNMP_TUNNEL_SUP = IBV_PORT_SNMP_TUNNEL_SUP,
            REINIT_SUP = IBV_PORT_REINIT_SUP,
            DEVICE_MGMT_SUP = IBV_PORT_DEVICE_MGMT_SUP,
            VENDOR_CLASS_SUP = IBV_PORT_VENDOR_CLASS_SUP,
            DR_NOTICE_SUP = IBV_PORT_DR_NOTICE_SUP,
            CAP_MASK_NOTICE_SUP = IBV_PORT_CAP_MASK_NOTICE_SUP,
            BOOT_MGMT_SUP = IBV_PORT_BOOT_MGMT_SUP,
            LINK_LATENCY_SUP = IBV_PORT_LINK_LATENCY_SUP,
            CLIENT_REG_SUP = IBV_PORT_CLIENT_REG_SUP,
            IP_BASED_GIDS = IBV_PORT_IP_BASED_GIDS
        };

        class Attributes : public ibv_port_attr {
            using ibv_port_attr::state;
            using ibv_port_attr::max_mtu;
            using ibv_port_attr::active_mtu;
            using ibv_port_attr::gid_tbl_len;
            using ibv_port_attr::port_cap_flags;
            using ibv_port_attr::max_msg_sz;
            using ibv_port_attr::bad_pkey_cntr;
            using ibv_port_attr::qkey_viol_cntr;
            using ibv_port_attr::pkey_tbl_len;
            using ibv_port_attr::lid;
            using ibv_port_attr::sm_lid;
            using ibv_port_attr::lmc;
            using ibv_port_attr::max_vl_num;
            using ibv_port_attr::sm_sl;
            using ibv_port_attr::subnet_timeout;
            using ibv_port_attr::init_type_reply;
            using ibv_port_attr::active_width;
            using ibv_port_attr::active_speed;
            using ibv_port_attr::phys_state;
            using ibv_port_attr::link_layer;
            using ibv_port_attr::reserved;
        public:
            /// Logical port state
            [[nodiscard]]
            constexpr State getState() const {
                return static_cast<State>(state);
            }

            /// Max MTU supported by port
            [[nodiscard]]
            constexpr Mtu getMaxMtu() const {
                return static_cast<Mtu>(max_mtu);
            }

            /// Actual MTU
            [[nodiscard]]
            constexpr Mtu getActiveMtu() const {
                return static_cast<Mtu>(active_mtu);
            }

            /// Length of source GID table
            [[nodiscard]]
            constexpr int getGidTblLen() const {
                return gid_tbl_len;
            }

            /// test port capabilities
            [[nodiscard]]
            constexpr bool hasCapability(CapabilityFlag flag) {
                const auto rawFlag = static_cast<ibv_port_cap_flags>(flag);
                return (port_cap_flags & rawFlag) == rawFlag;
            }

            /// Maximum message size
            [[nodiscard]]
            constexpr uint32_t getMaxMsgSize() const {
                return max_msg_sz;
            }

            /// Bad P_Key counter
            [[nodiscard]]
            constexpr uint32_t getBadPkeyCntr() const {
                return bad_pkey_cntr;
            }

            /// Q_Key violation counter
            [[nodiscard]]
            constexpr uint32_t getQkeyViolCntr() const {
                return qkey_viol_cntr;
            }

            /// Length of partition table
            [[nodiscard]]
            constexpr uint16_t getPkeyTblLen() const {
                return pkey_tbl_len;
            }

            /// Base port LID
            [[nodiscard]]
            constexpr uint16_t getLid() const {
                return lid;
            }

            /// SM LID
            [[nodiscard]]
            constexpr uint16_t getSmLid() const {
                return sm_lid;
            }

            /// LMC of LID
            [[nodiscard]]
            constexpr uint8_t getLmc() const {
                return lmc;
            }

            /// Maximum number of VLs
            [[nodiscard]]
            constexpr uint8_t getMaxVlNum() const {
                return max_vl_num;
            }

            /// SM service level
            [[nodiscard]]
            constexpr uint8_t getSmSl() const {
                return sm_sl;
            }

            /// Subnet propagation delay
            [[nodiscard]]
            constexpr uint8_t getSubnetTimeout() const {
                return subnet_timeout;
            }

            /// Type of initialization performed by SM
            [[nodiscard]]
            constexpr uint8_t getInitTypeReply() const {
                return init_type_reply;
            }

            /// Currently active link width
            [[nodiscard]]
            constexpr uint8_t getActiveWidth() const {
                return active_width;
            }

            /// Currently active link speed
            [[nodiscard]]
            constexpr uint8_t getActiveSpeed() const {
                return active_speed;
            }

            /// Physical port state
            [[nodiscard]]
            constexpr uint8_t getPhysState() const {
                return phys_state;
            }

            /// link layer protocol of the port
            [[nodiscard]]
            constexpr uint8_t getLinkLayer() const {
                return link_layer;
            }
        };

        static_assert(sizeof(Attributes) == sizeof(ibv_port_attr));
    } // namespace port

    namespace device {
        enum class CapabilityFlag : std::underlying_type_t<ibv_device_cap_flags> {
            RESIZE_MAX_WR = IBV_DEVICE_RESIZE_MAX_WR,
            BAD_PKEY_CNTR = IBV_DEVICE_BAD_PKEY_CNTR,
            BAD_QKEY_CNTR = IBV_DEVICE_BAD_QKEY_CNTR,
            RAW_MULTI = IBV_DEVICE_RAW_MULTI,
            AUTO_PATH_MIG = IBV_DEVICE_AUTO_PATH_MIG,
            CHANGE_PHY_PORT = IBV_DEVICE_CHANGE_PHY_PORT,
            UD_AV_PORT_ENFORCE = IBV_DEVICE_UD_AV_PORT_ENFORCE,
            CURR_QP_STATE_MOD = IBV_DEVICE_CURR_QP_STATE_MOD,
            SHUTDOWN_PORT = IBV_DEVICE_SHUTDOWN_PORT,
            INIT_TYPE = IBV_DEVICE_INIT_TYPE,
            PORT_ACTIVE_EVENT = IBV_DEVICE_PORT_ACTIVE_EVENT,
            SYS_IMAGE_GUID = IBV_DEVICE_SYS_IMAGE_GUID,
            RC_RNR_NAK_GEN = IBV_DEVICE_RC_RNR_NAK_GEN,
            SRQ_RESIZE = IBV_DEVICE_SRQ_RESIZE,
            N_NOTIFY_CQ = IBV_DEVICE_N_NOTIFY_CQ,
            MEM_WINDOW = IBV_DEVICE_MEM_WINDOW,
            UD_IP_CSUM = IBV_DEVICE_UD_IP_CSUM,
            XRC = IBV_DEVICE_XRC,
            MEM_MGT_EXTENSIONS = IBV_DEVICE_MEM_MGT_EXTENSIONS,
            MEM_WINDOW_TYPE_2A = IBV_DEVICE_MEM_WINDOW_TYPE_2A,
            MEM_WINDOW_TYPE_2B = IBV_DEVICE_MEM_WINDOW_TYPE_2B,
            RC_IP_CSUM = IBV_DEVICE_RC_IP_CSUM,
            RAW_IP_CSUM = IBV_DEVICE_RAW_IP_CSUM,
            MANAGED_FLOW_STEERING = IBV_DEVICE_MANAGED_FLOW_STEERING
        };

        enum class AtomicCapabilities : std::underlying_type_t<ibv_atomic_cap> {
            NONE = IBV_ATOMIC_NONE,
            HCA = IBV_ATOMIC_HCA,
            GLOB = IBV_ATOMIC_GLOB
        };

        class Attributes : public ibv_device_attr {
            using ibv_device_attr::fw_ver;
            using ibv_device_attr::node_guid;
            using ibv_device_attr::sys_image_guid;
            using ibv_device_attr::max_mr_size;
            using ibv_device_attr::page_size_cap;
            using ibv_device_attr::vendor_id;
            using ibv_device_attr::vendor_part_id;
            using ibv_device_attr::hw_ver;
            using ibv_device_attr::max_qp;
            using ibv_device_attr::max_qp_wr;
            using ibv_device_attr::device_cap_flags;
            using ibv_device_attr::max_sge;
            using ibv_device_attr::max_sge_rd;
            using ibv_device_attr::max_cq;
            using ibv_device_attr::max_cqe;
            using ibv_device_attr::max_mr;
            using ibv_device_attr::max_pd;
            using ibv_device_attr::max_qp_rd_atom;
            using ibv_device_attr::max_ee_rd_atom;
            using ibv_device_attr::max_res_rd_atom;
            using ibv_device_attr::max_qp_init_rd_atom;
            using ibv_device_attr::max_ee_init_rd_atom;
            using ibv_device_attr::atomic_cap;
            using ibv_device_attr::max_ee;
            using ibv_device_attr::max_rdd;
            using ibv_device_attr::max_mw;
            using ibv_device_attr::max_raw_ipv6_qp;
            using ibv_device_attr::max_raw_ethy_qp;
            using ibv_device_attr::max_mcast_grp;
            using ibv_device_attr::max_mcast_qp_attach;
            using ibv_device_attr::max_total_mcast_qp_attach;
            using ibv_device_attr::max_ah;
            using ibv_device_attr::max_fmr;
            using ibv_device_attr::max_map_per_fmr;
            using ibv_device_attr::max_srq;
            using ibv_device_attr::max_srq_wr;
            using ibv_device_attr::max_srq_sge;
            using ibv_device_attr::max_pkeys;
            using ibv_device_attr::local_ca_ack_delay;
            using ibv_device_attr::phys_port_cnt;
        public:
            /// The Firmware verssion
            [[nodiscard]]
            constexpr const char *getFwVer() const {
                return static_cast<const char *>(fw_ver);
            }

            /// Node GUID (in network byte order)
            [[nodiscard]]
            constexpr uint64_t getNodeGuid() const {
                return node_guid;
            }

            /// System image GUID (in network byte order)
            [[nodiscard]]
            constexpr uint64_t getSysImageGuid() const {
                return sys_image_guid;
            }

            /// Largest contiguous block that can be registered
            [[nodiscard]]
            constexpr uint64_t getMaxMrSize() const {
                return max_mr_size;
            }

            /// Supported memory shift sizes
            [[nodiscard]]
            constexpr uint64_t getPageSizeCap() const {
                return page_size_cap;
            }

            /// Vendor ID, per IEEE
            [[nodiscard]]
            constexpr uint32_t getVendorId() const {
                return vendor_id;
            }

            /// Vendor supplied part ID
            [[nodiscard]]
            constexpr uint32_t getVendorPartId() const {
                return vendor_part_id;
            }

            /// Hardware version
            [[nodiscard]]
            constexpr uint32_t getHwVer() const {
                return hw_ver;
            }

            /// Maximum number of supported QPs
            [[nodiscard]]
            constexpr int getMaxQp() const {
                return max_qp;
            }

            /// Maximum number of outstanding WR on any work queue
            [[nodiscard]]
            constexpr int getMaxQpWr() const {
                return max_qp_wr;
            }

            /// Check for a capability
            [[nodiscard]]
            constexpr bool hasCapability(CapabilityFlag flag) const {
                const auto rawFlag = static_cast<ibv_device_cap_flags>(flag);
                return (device_cap_flags & rawFlag) == rawFlag;
            }

            /// Maximum number of s/g per WR for SQ & RQ of QP for non RDMA Read operations
            [[nodiscard]]
            constexpr int getMaxSge() const {
                return max_sge;
            }

            /// Maximum number of s/g per WR for RDMA Read operations
            [[nodiscard]]
            constexpr int getMaxSgeRd() const {
                return max_sge_rd;
            }

            /// Maximum number of supported CQs
            [[nodiscard]]
            constexpr int getMaxCq() const {
                return max_cq;
            }

            /// Maximum number of CQE capacity per CQ
            [[nodiscard]]
            constexpr int getMaxCqe() const {
                return max_cqe;
            }

            /// Maximum number of supported MRs
            [[nodiscard]]
            constexpr int getMaxMr() const {
                return max_mr;
            }

            /// Maximum number of supported PDs
            [[nodiscard]]
            constexpr int getMaxPd() const {
                return max_pd;
            }

            /// Maximum number of RDMA Read & Atomic operations that can be outstanding per QP
            [[nodiscard]]
            constexpr int getMaxQpRdAtom() const {
                return max_qp_rd_atom;
            }

            /// Maximum number of RDMA Read & Atomic operations that can be outstanding per EEC
            [[nodiscard]]
            constexpr int getMaxEeRdAtom() const {
                return max_ee_rd_atom;
            }

            /// Maximum number of resources used for RDMA Read & Atomic operations by this HCA as the Target
            [[nodiscard]]
            constexpr int getMaxResRdAtom() const {
                return max_res_rd_atom;
            }

            /// Maximum depth per QP for initiation of RDMA Read & Atomic operations
            [[nodiscard]]
            constexpr int getMaxQpInitRdAtom() const {
                return max_qp_init_rd_atom;
            }

            /// Maximum depth per EEC for initiation of RDMA Read & Atomic operations
            [[nodiscard]]
            constexpr int getMaxEeInitRdAtom() const {
                return max_ee_init_rd_atom;
            }

            /// Atomic operations support level
            [[nodiscard]]
            constexpr AtomicCapabilities getAtomicCap() const {
                return static_cast<AtomicCapabilities>(atomic_cap);
            }

            /// Maximum number of supported EE contexts
            [[nodiscard]]
            constexpr int getMaxEe() const {
                return max_ee;
            }

            /// Maximum number of supported RD domains
            [[nodiscard]]
            constexpr int getMaxRdd() const {
                return max_rdd;
            }

            /// Maximum number of supported MWs
            [[nodiscard]]
            constexpr int getMaxMw() const {
                return max_mw;
            }

            /// Maximum number of supported raw IPv6 datagram QPs
            [[nodiscard]]
            constexpr int getMaxRawIpv6Qp() const {
                return max_raw_ipv6_qp;
            }

            /// Maximum number of supported Ethertype datagram QPs
            [[nodiscard]]
            constexpr int getMaxRawEthyQp() const {
                return max_raw_ethy_qp;
            }

            /// Maximum number of supported multicast groups
            [[nodiscard]]
            constexpr int getMaxMcastGrp() const {
                return max_mcast_grp;
            }

            /// Maximum number of QPs per multicast group which can be attached
            [[nodiscard]]
            constexpr int getMaxMcastQpAttach() const {
                return max_mcast_qp_attach;
            }

            /// Maximum number of QPs which can be attached to multicast groups
            [[nodiscard]]
            constexpr int getMaxTotalMcastQpAttach() const {
                return max_total_mcast_qp_attach;
            }

            /// Maximum number of supported address handles
            [[nodiscard]]
            constexpr int getMaxAh() const {
                return max_ah;
            }

            /// Maximum number of supported FMRs
            [[nodiscard]]
            constexpr int getMaxFmr() const {
                return max_fmr;
            }

            /// Maximum number of (re)maps per FMR before an unmap operation in required
            [[nodiscard]]
            constexpr int getMaxMapPerFmr() const {
                return max_map_per_fmr;
            }

            /// Maximum number of supported SRQs
            [[nodiscard]]
            constexpr int getMaxSrq() const {
                return max_srq;
            }

            /// Maximum number of WRs per SRQ
            [[nodiscard]]
            constexpr int getMaxSrqWr() const {
                return max_srq_wr;
            }

            /// Maximum number of s/g per SRQ
            [[nodiscard]]
            constexpr int getMaxSrqSge() const {
                return max_srq_sge;
            }

            /// Maximum number of partitions
            [[nodiscard]]
            constexpr uint16_t getMaxPkeys() const {
                return max_pkeys;
            }

            /// Local CA ack delay
            [[nodiscard]]
            constexpr uint8_t getLocalCaAckDelay() const {
                return local_ca_ack_delay;
            }

            /// Number of physical ports
            [[nodiscard]]
            constexpr uint8_t getPhysPortCnt() const {
                return phys_port_cnt;
            }
        };

        static_assert(sizeof(Attributes) == sizeof(ibv_device_attr));

        class Device : public ibv_device, public internal::PointerOnly {
            using ibv_device::_ops;
            using ibv_device::node_type;
            using ibv_device::transport_type;
            using ibv_device::name;
            using ibv_device::dev_name;
            using ibv_device::dev_path;
            using ibv_device::ibdev_path;
        public:
            [[nodiscard]]
            const char *getName() {
                return ibv_get_device_name(this);
            }

            [[nodiscard]]
            uint64_t getGUID() {
                return ibv_get_device_guid(this);
            }

            /// Open a RDMA device context
            [[nodiscard]]
            std::unique_ptr<context::Context> open() {
                using Ctx = context::Context;
                const auto context = ibv_open_device(this);
                internal::checkPtr("ibv_open_device", context);
                return std::unique_ptr<Ctx>(reinterpret_cast<Ctx *>(context));
            }
        };

        static_assert(sizeof(Device) == sizeof(ibv_device));

        class DeviceList {
            int num_devices = 0; // needs to be initialized first
            Device **devices = nullptr;

        public:
            /// Get a list of available RDMA devices
            DeviceList() : devices(reinterpret_cast<Device **>(ibv_get_device_list(&num_devices))) {
                internal::checkPtr("ibv_get_device_list", devices);
            }

            ~DeviceList() {
                if (devices != nullptr) {
                    ibv_free_device_list(reinterpret_cast<ibv_device **>(devices));
                }
            }

            DeviceList(const DeviceList &) = delete;

            DeviceList &operator=(const DeviceList &) = delete;

            DeviceList(DeviceList &&other) noexcept {
                devices = other.devices;
                other.devices = nullptr;
                num_devices = other.num_devices;
                other.num_devices = 0;
            }

            constexpr DeviceList &operator=(DeviceList &&other) noexcept {
                if (devices != nullptr) {
                    ibv_free_device_list(reinterpret_cast<ibv_device **>(devices));
                }
                devices = other.devices;
                other.devices = nullptr;
                num_devices = other.num_devices;
                other.num_devices = 0;
                return *this;
            }

            [[nodiscard]]
            constexpr Device **begin() {
                return devices;
            }

            [[nodiscard]]
            constexpr Device **end() {
                return &devices[num_devices];
            }

            [[nodiscard]]
            constexpr size_t size() const {
                return static_cast<size_t>(num_devices);
            }

            [[nodiscard]]
            constexpr Device *&operator[](int idx) {
                return devices[idx];
            }
        };
    }  // namespace device

    namespace memoryregion {
        enum class ReregFlag : std::underlying_type_t<ibv_rereg_mr_flags> {
            CHANGE_TRANSLATION = IBV_REREG_MR_CHANGE_TRANSLATION,
            CHANGE_PD = IBV_REREG_MR_CHANGE_PD,
            CHANGE_ACCESS = IBV_REREG_MR_CHANGE_ACCESS,
            KEEP_VALID = IBV_REREG_MR_KEEP_VALID,
            FLAGS_SUPPORTED = IBV_REREG_MR_FLAGS_SUPPORTED
        };

        enum class ReregErrorCode : std::underlying_type_t<ibv_rereg_mr_err_code> {
            INPUT = IBV_REREG_MR_ERR_INPUT,
            DONT_FORK_NEW = IBV_REREG_MR_ERR_DONT_FORK_NEW,
            DO_FORK_OLD = IBV_REREG_MR_ERR_DO_FORK_OLD,
            CMD = IBV_REREG_MR_ERR_CMD,
            CMD_AND_DO_FORK_NEW = IBV_REREG_MR_ERR_CMD_AND_DO_FORK_NEW
        };

        [[nodiscard]]
        inline std::string to_string(ReregErrorCode ec) {
            switch (ec) {
                case ReregErrorCode::INPUT:
                    return "IBV_REREG_MR_ERR_INPUT";
                case ReregErrorCode::DONT_FORK_NEW:
                    return "IBV_REREG_MR_ERR_DONT_FORK_NEW";
                case ReregErrorCode::DO_FORK_OLD:
                    return "IBV_REREG_MR_ERR_DO_FORK_OLD";
                case ReregErrorCode::CMD:
                    return "IBV_REREG_MR_ERR_CMD";
                case ReregErrorCode::CMD_AND_DO_FORK_NEW:
                    return "IBV_REREG_MR_ERR_CMD_AND_DO_FORK_NEW";
            }
            __builtin_unreachable();
        }

        struct Slice : public ibv_sge {
        };

        struct RemoteAddress {
            uint64_t address;
            uint32_t rkey;

            [[nodiscard]]
            constexpr RemoteAddress offset(uint64_t offset) const noexcept {
                return RemoteAddress{address + offset, rkey};
            }
        };

        class MemoryRegion : public ibv_mr, public internal::PointerOnly {
            using ibv_mr::context;
            using ibv_mr::pd;
            using ibv_mr::addr;
            using ibv_mr::length;
            using ibv_mr::handle;
            using ibv_mr::lkey;
            using ibv_mr::rkey;
        public:
            static void *operator new(std::size_t) noexcept = delete;

            static void operator delete(void *ptr) noexcept {
                const auto status = ibv_dereg_mr(reinterpret_cast<ibv_mr *>(ptr));
                internal::checkStatusNoThrow("ibv_dereg_mr", status);
            }

            [[nodiscard]]
            context::Context *getContext() const {
                return reinterpret_cast<context::Context *>(context);
            }

            [[nodiscard]]
            protectiondomain::ProtectionDomain *getPd() const {
                return reinterpret_cast<protectiondomain::ProtectionDomain *>(pd);
            }

            [[nodiscard]]
            constexpr void *getAddr() const {
                return addr;
            }

            [[nodiscard]]
            constexpr size_t getLength() const {
                return length;
            }

            [[nodiscard]]
            constexpr uint32_t getHandle() const {
                return handle;
            }

            [[nodiscard]]
            constexpr uint32_t getLkey() const {
                return lkey;
            }

            [[nodiscard]]
            constexpr uint32_t getRkey() const {
                return rkey;
            }

            [[nodiscard]]
            Slice getSlice() {
                return Slice{{reinterpret_cast<uintptr_t>(addr), static_cast<uint32_t>(length), lkey}};
            }

            [[nodiscard]]
            Slice getSlice(uint32_t offset, uint32_t sliceLength) {
                return Slice{{reinterpret_cast<uintptr_t>(addr) + offset, sliceLength, lkey}};
            }

            [[nodiscard]]
            RemoteAddress getRemoteAddress() {
                return RemoteAddress{reinterpret_cast<uint64_t>(addr), rkey};
            }

            /// Reregister the MemoryRegion to modify the attribotes of an existing MemoryRegion,
            /// reusing resources whenever possible
            void reRegister(std::initializer_list<ReregFlag> changeFlags, protectiondomain::ProtectionDomain *newPd,
                            void *newAddr, size_t newLength, std::initializer_list<AccessFlag> accessFlags) {
                int changes = 0;
                for (auto change : changeFlags) {
                    changes |= static_cast<ibv_rereg_mr_flags>(change);
                }
                int access = 0;
                for (auto accessFlag : accessFlags) {
                    access |= static_cast<ibv_access_flags>(accessFlag);
                }
                const auto status = // TODO
                        ibv_rereg_mr(this, changes, reinterpret_cast<ibv_pd *>(newPd), newAddr, newLength, access);

                if (status != 0) {
                    const auto res = static_cast<ReregErrorCode>(status);
                    throw std::runtime_error("ibv_rereg_mr failed with: " + to_string(res));
                }
            }
        };

        static_assert(sizeof(MemoryRegion) == sizeof(ibv_mr));

        [[nodiscard]]
        inline std::string to_string(const MemoryRegion &mr) {
            std::ostringstream addr;
            addr << mr.getAddr();
            return std::string("ptr=") + addr.str() + " size=" + std::to_string(mr.getLength()) + " key={..}";
        }
    } // namespace memoryregion

    namespace workrequest {
        // internal
        enum class Opcode : std::underlying_type_t<ibv_wr_opcode> {
            RDMA_WRITE = IBV_WR_RDMA_WRITE,
            RDMA_WRITE_WITH_IMM = IBV_WR_RDMA_WRITE_WITH_IMM,
            SEND = IBV_WR_SEND,
            SEND_WITH_IMM = IBV_WR_SEND_WITH_IMM,
            RDMA_READ = IBV_WR_RDMA_READ,
            ATOMIC_CMP_AND_SWP = IBV_WR_ATOMIC_CMP_AND_SWP,
            ATOMIC_FETCH_AND_ADD = IBV_WR_ATOMIC_FETCH_AND_ADD,
            LOCAL_INV = IBV_WR_LOCAL_INV,
            BIND_MW = IBV_WR_BIND_MW,
            SEND_WITH_INV = IBV_WR_SEND_WITH_INV
        };

        enum class Flags : std::underlying_type_t<ibv_send_flags> {
            FENCE = IBV_SEND_FENCE, /// The fence Indicator (valid for RC)
            SIGNALED = IBV_SEND_SIGNALED, /// The completion notification indicator. Relevant only if QP was created with setSignalAll(true)
            SOLICITED = IBV_SEND_SOLICITED, /// The solocited event indicator. Valid for Send / Write with immediate
            INLINE = IBV_SEND_INLINE, /// Send data as inline data. Valid for Send / Write
            IP_CSUM = IBV_SEND_IP_CSUM /// Offload the IBv4 and TCP/UDP checksum calculation. Valid when the device supports checksum offload (see Context.queryAttributes())
        };

        struct SendWr : public ibv_send_wr {
        private:
            using ibv_send_wr::wr_id;
            using ibv_send_wr::next;
            using ibv_send_wr::sg_list;
            using ibv_send_wr::num_sge;
            using ibv_send_wr::opcode;
            using ibv_send_wr::send_flags;
            using ibv_send_wr::imm_data;
            using ibv_send_wr::invalidate_rkey;
            using ibv_send_wr::wr;
            using ibv_send_wr::qp_type;
            using ibv_send_wr::bind_mw;
            using ibv_send_wr::tso;
        public:
            constexpr SendWr() : ibv_send_wr{} {}

            constexpr void setId(uint64_t id) {
                wr_id = id;
            }

            [[nodiscard]]
            constexpr uint64_t getId() const {
                return wr_id;
            }

            constexpr void setNext(SendWr *wrList) {
                next = wrList;
            }

            constexpr void setSge(memoryregion::Slice *scatterGatherArray, int size) {
                sg_list = scatterGatherArray;
                num_sge = size;
            }

            constexpr void setFlag(Flags flag) {
                send_flags |= static_cast<ibv_send_flags>(flag);
            }

            constexpr void setFence() {
                setFlag(Flags::FENCE);
            }

            constexpr void setSignaled() {
                setFlag(Flags::SIGNALED);
            }

            constexpr void setSolicited() {
                setFlag(Flags::SOLICITED);
            }

            constexpr void setInline() {
                setFlag(Flags::INLINE);
            }

            constexpr void setIpCsum() {
                setFlag(Flags::IP_CSUM);
            }

            constexpr void setFlags(std::initializer_list<Flags> flags) {
                send_flags = 0;
                for (const auto flag : flags) {
                    setFlag(flag);
                }
            }

        protected:
            constexpr void setOpcode(Opcode opcode) {
                this->opcode = static_cast<ibv_wr_opcode>(opcode);
            }

            constexpr void setImmData(uint32_t data) {
                imm_data = data;
            }

            [[nodiscard]]
            constexpr decltype(wr) &getWr() {
                return wr;
            }
        };

        static_assert(sizeof(SendWr) == sizeof(ibv_send_wr));

        // internal
        struct Rdma : SendWr {
            constexpr void setRemoteAddress(memoryregion::RemoteAddress remoteAddress) {
                getWr().rdma.remote_addr = remoteAddress.address;
                getWr().rdma.rkey = remoteAddress.rkey;
            }

            [[deprecated]]
            constexpr void setRemoteAddress(uint64_t remote_addr, uint32_t rkey) {
                getWr().rdma.remote_addr = remote_addr;
                getWr().rdma.rkey = rkey;
            }
        };

        struct Write : Rdma {
            constexpr Write() {
                SendWr::setOpcode(Opcode::RDMA_WRITE);
            }
        };

        struct WriteWithImm : Write {
            constexpr WriteWithImm() {
                WriteWithImm::setOpcode(Opcode::RDMA_WRITE_WITH_IMM);
            }

            using SendWr::setImmData;
        };

        struct Send : SendWr {
            constexpr Send() {
                SendWr::setOpcode(Opcode::SEND);
            }

            void setUDAddressHandle(ah::AddressHandle &ah) {
                getWr().ud.ah = &ah;
            }

            constexpr void setUDRemoteQueue(uint32_t qpn, uint32_t qkey) {
                getWr().ud.remote_qpn = qpn;
                getWr().ud.remote_qkey = qkey;
            }
        };

        struct SendWithImm : SendWr {
            constexpr SendWithImm() {
                SendWr::setOpcode(Opcode::SEND_WITH_IMM);
            }

            using SendWr::setImmData;
        };

        struct Read : Rdma {
            constexpr Read() {
                SendWr::setOpcode(Opcode::RDMA_READ);
            }
        };

        // internal
        struct Atomic : SendWr {
            constexpr void setRemoteAddress(memoryregion::RemoteAddress remoteAddress) {
                getWr().atomic.remote_addr = remoteAddress.address;
                getWr().atomic.rkey = remoteAddress.rkey;
            }

            [[deprecated]]
            constexpr void setRemoteAddress(uint64_t remote_addr, uint32_t rkey) {
                getWr().atomic.remote_addr = remote_addr;
                getWr().atomic.rkey = rkey;
            }
        };

        struct AtomicCompareSwap : Atomic {
            constexpr AtomicCompareSwap() {
                SendWr::setOpcode(Opcode::ATOMIC_CMP_AND_SWP);
            }

            constexpr AtomicCompareSwap(uint64_t compare, uint64_t swap) : AtomicCompareSwap() {
                setCompareValue(compare);
                setSwapValue(swap);
            }

            constexpr void setCompareValue(uint64_t value) {
                getWr().atomic.compare_add = value;
            }

            constexpr void setSwapValue(uint64_t value) {
                getWr().atomic.swap = value;
            }
        };

        struct AtomicFetchAdd : Atomic {
            constexpr AtomicFetchAdd() {
                SendWr::setOpcode(Opcode::ATOMIC_FETCH_AND_ADD);
            }

            explicit constexpr AtomicFetchAdd(uint64_t value) : AtomicFetchAdd() {
                setAddValue(value);
            }

            constexpr void setAddValue(uint64_t value) {
                getWr().atomic.compare_add = value;
            }
        };

        class Recv : public ibv_recv_wr {
            using ibv_recv_wr::wr_id;
            using ibv_recv_wr::next;
            using ibv_recv_wr::sg_list;
            using ibv_recv_wr::num_sge;
        public:
            /// User defined WR ID
            constexpr void setId(uint64_t id) {
                wr_id = id;
            }

            /// User defined WR ID
            [[nodiscard]]
            constexpr uint64_t getId() const {
                return wr_id;
            }

            /// Pointer to next WR in list, NULL if last WR
            constexpr void setNext(Recv *next) {
                this->next = next;
            }

            /// The Scatter/Gather array with size
            constexpr void setSge(memoryregion::Slice *scatterGatherArray, int size) {
                sg_list = scatterGatherArray;
                num_sge = size;
            }
        };

        static_assert(sizeof(Recv) == sizeof(ibv_recv_wr));

        /// Helper class for simple workrequests, that only use a single Scatter/Gather entry, aka only write to
        /// continuous memory
        template<class SendWorkRequest>
        class Simple : public SendWorkRequest {
            static_assert(std::is_base_of<SendWr, SendWorkRequest>::value or
                          std::is_base_of<Recv, SendWorkRequest>::value);

            memoryregion::Slice slice{};

        public:
            using SendWorkRequest::SendWorkRequest;

            constexpr void setLocalAddress(const memoryregion::Slice &sge) {
                SendWorkRequest::setSge(&slice, 1);

                slice = sge;
            }
        };
    } // namespace workrequest

    namespace memorywindow {
        enum class Type : std::underlying_type_t<ibv_mw_type> {
            TYPE_1 = IBV_MW_TYPE_1,
            TYPE_2 = IBV_MW_TYPE_2
        };

        class BindInfo : public ibv_mw_bind_info {
            using ibv_mw_bind_info::mr;
            using ibv_mw_bind_info::addr;
            using ibv_mw_bind_info::length;
            using ibv_mw_bind_info::mw_access_flags;
        public:
            /// The MR to bind the MW to
            void setMr(memoryregion::MemoryRegion &memoryregion) {
                mr = &memoryregion;
            }

            /// The address the MW should start at
            constexpr void setAddr(uint64_t addr) {
                this->addr = addr;
            }

            /// The length (in bytes) the MW should span
            constexpr void setLength(uint64_t length) {
                this->length = length;
            }

            /// Access flags to the MW
            constexpr void setMwAccessFlags(std::initializer_list<AccessFlag> accessFlags) {
                mw_access_flags = 0;
                for (auto accessFlag : accessFlags) {
                    mw_access_flags |= static_cast<ibv_access_flags>(accessFlag);
                }
            }
        };

        static_assert(sizeof(BindInfo) == sizeof(ibv_mw_bind_info));

        class Bind : public ibv_mw_bind {
            using ibv_mw_bind::wr_id;
            using ibv_mw_bind::send_flags;
            using ibv_mw_bind::bind_info;
        public:
            /// User defined WR ID
            constexpr void setWrId(uint64_t id) {
                wr_id = id;
            }

            // The send flags for the bind request
            constexpr void setSendFlags(std::initializer_list<workrequest::Flags> flags) {
                send_flags = 0;
                for (auto flag : flags) {
                    send_flags |= static_cast<ibv_send_flags>(flag);
                }
            }

            /// MW bind information
            [[nodiscard]]
            BindInfo &getBindInfo() {
                return reinterpret_cast<BindInfo &>(bind_info);
            }
        };

        static_assert(sizeof(Bind) == sizeof(ibv_mw_bind));

        class MemoryWindow : public ibv_mw, public internal::PointerOnly {
            using ibv_mw::context;
            using ibv_mw::pd;
            using ibv_mw::rkey;
            using ibv_mw::handle;
            using ibv_mw::type;
        public:
            static void *operator new(std::size_t) noexcept = delete;

            static void operator delete(void *ptr) noexcept {
                const auto status = ibv_dealloc_mw(reinterpret_cast<ibv_mw *>(ptr));
                internal::checkStatusNoThrow("ibv_dealloc_mw", status);
            }

            [[nodiscard]]
            context::Context *getContext() const {
                return reinterpret_cast<context::Context *>(context);
            }

            [[nodiscard]]
            protectiondomain::ProtectionDomain *getPd() const {
                return reinterpret_cast<protectiondomain::ProtectionDomain *>(pd);
            }

            [[nodiscard]]
            constexpr uint32_t getRkey() const {
                return rkey;
            }

            [[nodiscard]]
            constexpr uint32_t getHandle() const {
                return handle;
            }

            [[nodiscard]]
            constexpr Type getType() {
                return static_cast<Type>(type);
            }
        };

        static_assert(sizeof(MemoryWindow) == sizeof(ibv_mw));
    } // namespace memorywindow

    namespace srq {
        enum class AttributeMask : std::underlying_type_t<ibv_srq_attr_mask> {
            MAX_WR = IBV_SRQ_MAX_WR,
            LIMIT = IBV_SRQ_LIMIT
        };

        enum class Type : std::underlying_type_t<ibv_srq_type> {
            BASIC = IBV_SRQT_BASIC,
            XRC = IBV_SRQT_XRC
        };

        enum class InitAttributeMask : std::underlying_type_t<ibv_srq_init_attr_mask> {
            TYPE = IBV_SRQ_INIT_ATTR_TYPE,
            PD = IBV_SRQ_INIT_ATTR_PD,
            XRCD = IBV_SRQ_INIT_ATTR_XRCD,
            CQ = IBV_SRQ_INIT_ATTR_CQ,
            RESERVED = IBV_SRQ_INIT_ATTR_RESERVED
        };

        class Attributes : public ibv_srq_attr {
            using ibv_srq_attr::max_wr;
            using ibv_srq_attr::max_sge;
            using ibv_srq_attr::srq_limit;
        public:
            explicit constexpr Attributes(uint32_t max_wr = 0, uint32_t max_sge = 0, uint32_t srq_limit = 0) :
                    ibv_srq_attr{max_wr, max_sge, srq_limit} {}
        };

        static_assert(sizeof(Attributes) == sizeof(ibv_srq_attr));

        class InitAttributes : public ibv_srq_init_attr {
            using ibv_srq_init_attr::srq_context;
            using ibv_srq_init_attr::attr;
        public:
            explicit constexpr InitAttributes(Attributes attrs = Attributes(), void *context = nullptr) :
                    ibv_srq_init_attr{context, attrs} {}
        };

        static_assert(sizeof(InitAttributes) == sizeof(ibv_srq_init_attr));

        class SharedReceiveQueue : public ibv_srq, public internal::PointerOnly {
            using ibv_srq::context;
            using ibv_srq::srq_context;
            using ibv_srq::pd;
            using ibv_srq::handle;
            using ibv_srq::mutex;
            using ibv_srq::cond;
            using ibv_srq::events_completed;
        public:
            static void *operator new(std::size_t) noexcept = delete;

            static void operator delete(void *ptr) noexcept {
                const auto status = ibv_destroy_srq(reinterpret_cast<ibv_srq *>(ptr));
                internal::checkStatusNoThrow("ibv_destroy_srq", status);
            }

            /// Modify the attributes of the SharedReceiveQueue. Which attributes are specified in modifiedAttrs
            void modify(Attributes &attr, std::initializer_list<AttributeMask> modifiedAttrs) {
                int modifiedMask = 0;
                for (auto mod : modifiedAttrs) {
                    modifiedMask |= static_cast<ibv_srq_attr_mask>(mod);
                }

                const auto status = ibv_modify_srq(this, &attr, modifiedMask);
                internal::checkStatus("ibv_modify_srq", status);
            }

            /// Query the current attributes of the SharedReceiveQueue and return them in res
            void query(Attributes &res) {
                const auto status = ibv_query_srq(this, &res);
                internal::checkStatus("ibv_query_srq", status);
            }

            /// Query the current attributes of the SharedReceiveQueue
            [[nodiscard]]
            Attributes query() {
                Attributes res{};
                query(res);
                return res;
            }

            /// Query the associated SRQ number
            [[nodiscard]]
            uint32_t getNumber() {
                uint32_t num = 0;
                const auto status = ibv_get_srq_num(this, &num);
                internal::checkStatus("ibv_get_srq_num", status);
                return num;
            }

            /// Post Recv workrequests to this SharedReceiveQueue, which can possibly be chained
            /// might throw and set the causing workrequest in badWr
            void postRecv(workrequest::Recv &wr, workrequest::Recv *&badWr) {
                const auto status = ibv_post_srq_recv(this, &wr, reinterpret_cast<ibv_recv_wr **>(&badWr));
                internal::checkStatus("ibv_post_srq_recv", status);
            }
        };

        static_assert(sizeof(SharedReceiveQueue) == sizeof(ibv_srq));
    } // namespace srq

    namespace xrcd {
        enum class InitAttributesMask : std::underlying_type_t<ibv_xrcd_init_attr_mask> {
            FD = IBV_XRCD_INIT_ATTR_FD,
            OFLAGS = IBV_XRCD_INIT_ATTR_OFLAGS,
            RESERVED = IBV_XRCD_INIT_ATTR_RESERVED
        };

        enum class OpenFlags : int {
            CREAT = O_CREAT, /// The XRCD should be created, if it does not already exists
            EXCL = O_EXCL /// Open the XRCD exclusively. Opening will fail if not possible
        };

        class InitAttributes : public ibv_xrcd_init_attr {
            using ibv_xrcd_init_attr::comp_mask;
            using ibv_xrcd_init_attr::fd;
            using ibv_xrcd_init_attr::oflags;
        public:
            constexpr void setValidComponents(std::initializer_list<InitAttributesMask> masks) {
                uint32_t newMask = 0;
                for (auto mask : masks) {
                    newMask |= static_cast<uint32_t>(mask);
                }
                this->comp_mask = newMask;
            }

            /// If fd equals -1, no inode is associated with the XRCD
            constexpr void setFd(int fd) {
                this->fd = fd;
            }

            constexpr void setOflags(std::initializer_list<OpenFlags> oflags) {
                int flags = 0;
                for (auto flag : oflags) {
                    flags |= static_cast<int>(flag);
                }
                this->oflags = flags;
            }
        };

        static_assert(sizeof(InitAttributes) == sizeof(ibv_xrcd_init_attr));

        class ExtendedConnectionDomain : public ibv_xrcd, public internal::PointerOnly {
            using ibv_xrcd::context;
        public:
            static void *operator new(std::size_t) noexcept = delete;

            static void operator delete(void *ptr) noexcept {
                const auto status = ibv_close_xrcd(reinterpret_cast<ibv_xrcd *>(ptr));
                internal::checkStatusNoThrow("ibv_close_xrcd", status);
            }
        };

        static_assert(sizeof(ExtendedConnectionDomain) == sizeof(ibv_xrcd));
    } // namespace xrcd

    namespace queuepair {
        enum class Type : std::underlying_type_t<ibv_qp_type> {
            RC = IBV_QPT_RC,
            UC = IBV_QPT_UC,
            UD = IBV_QPT_UD,
            RAW_PACKET = IBV_QPT_RAW_PACKET,
            XRC_SEND = IBV_QPT_XRC_SEND,
            XRC_RECV = IBV_QPT_XRC_RECV
        };

        enum class InitAttrMask : std::underlying_type_t<ibv_qp_init_attr_mask> {
            PD = IBV_QP_INIT_ATTR_PD,
            XRCD = IBV_QP_INIT_ATTR_XRCD,
            CREATE_FLAGS = IBV_QP_INIT_ATTR_CREATE_FLAGS,
            RESERVED = IBV_QP_INIT_ATTR_RESERVED
        };

        enum class CreateFlags : std::underlying_type_t<ibv_qp_create_flags> {
            BLOCK_SELF_MCAST_LB = IBV_QP_CREATE_BLOCK_SELF_MCAST_LB,
            SCATTER_FCS = IBV_QP_CREATE_SCATTER_FCS
        };

        enum class OpenAttrMask : std::underlying_type_t<ibv_qp_open_attr_mask> {
            NUM = IBV_QP_OPEN_ATTR_NUM,
            XRCD = IBV_QP_OPEN_ATTR_XRCD,
            CONTEXT = IBV_QP_OPEN_ATTR_CONTEXT,
            TYPE = IBV_QP_OPEN_ATTR_TYPE,
            RESERVED = IBV_QP_OPEN_ATTR_RESERVED
        };

        enum class AttrMask : std::underlying_type_t<ibv_qp_attr_mask> {
            STATE = IBV_QP_STATE,
            CUR_STATE = IBV_QP_CUR_STATE,
            EN_SQD_ASYNC_NOTIFY = IBV_QP_EN_SQD_ASYNC_NOTIFY,
            ACCESS_FLAGS = IBV_QP_ACCESS_FLAGS,
            PKEY_INDEX = IBV_QP_PKEY_INDEX,
            PORT = IBV_QP_PORT,
            QKEY = IBV_QP_QKEY,
            AV = IBV_QP_AV,
            PATH_MTU = IBV_QP_PATH_MTU,
            TIMEOUT = IBV_QP_TIMEOUT,
            RETRY_CNT = IBV_QP_RETRY_CNT,
            RNR_RETRY = IBV_QP_RNR_RETRY,
            RQ_PSN = IBV_QP_RQ_PSN,
            MAX_QP_RD_ATOMIC = IBV_QP_MAX_QP_RD_ATOMIC,
            ALT_PATH = IBV_QP_ALT_PATH,
            MIN_RNR_TIMER = IBV_QP_MIN_RNR_TIMER,
            SQ_PSN = IBV_QP_SQ_PSN,
            MAX_DEST_RD_ATOMIC = IBV_QP_MAX_DEST_RD_ATOMIC,
            PATH_MIG_STATE = IBV_QP_PATH_MIG_STATE,
            CAP = IBV_QP_CAP,
            DEST_QPN = IBV_QP_DEST_QPN
        };

        enum class State : std::underlying_type_t<ibv_qp_state> {
            RESET = IBV_QPS_RESET,
            INIT = IBV_QPS_INIT,
            RTR = IBV_QPS_RTR,
            RTS = IBV_QPS_RTS,
            SQD = IBV_QPS_SQD,
            SQE = IBV_QPS_SQE,
            ERR = IBV_QPS_ERR,
            UNKNOWN = IBV_QPS_UNKNOWN
        };

        [[nodiscard]]
        inline std::string to_string(State state) {
            switch (state) {
                case State::RESET:
                    return "IBV_QPS_RESET";
                case State::INIT:
                    return "IBV_QPS_INIT";
                case State::RTR:
                    return "IBV_QPS_RTR";
                case State::RTS:
                    return "IBV_QPS_RTS";
                case State::SQD:
                    return "IBV_QPS_SQD";
                case State::SQE:
                    return "IBV_QPS_SQE";
                case State::ERR:
                    return "IBV_QPS_ERR";
                case State::UNKNOWN:
                    return "IBV_QPS_UNKNOWN";
            }
            __builtin_unreachable();
        }

        enum class MigrationState : std::underlying_type_t<ibv_mig_state> {
            MIGRATED = IBV_MIG_MIGRATED,
            REARM = IBV_MIG_REARM,
            ARMED = IBV_MIG_ARMED
        };

        [[nodiscard]]
        inline std::string to_string(MigrationState ms) {
            switch (ms) {
                case MigrationState::MIGRATED:
                    return "IBV_MIG_MIGRATED";
                case MigrationState::REARM:
                    return "IBV_MIG_REARM";
                case MigrationState::ARMED:
                    return "IBV_MIG_ARMED";
            }
            __builtin_unreachable();
        }

        class Capabilities : public ibv_qp_cap {
            using ibv_qp_cap::max_send_wr;
            using ibv_qp_cap::max_recv_wr;
            using ibv_qp_cap::max_send_sge;
            using ibv_qp_cap::max_recv_sge;
            using ibv_qp_cap::max_inline_data;
        public:
            /// Max number of outstanding workrequests in the sendqueue
            [[nodiscard]]
            constexpr uint32_t getMaxSendWr() const {
                return max_send_wr;
            }

            /// Max number of outstanding workrequests in the receivequeue
            [[nodiscard]]
            constexpr uint32_t getMaxRecvWr() const {
                return max_recv_wr;
            }

            /// Max number of scatter/gather elements of each workrequest in the sendqueue
            [[nodiscard]]
            constexpr uint32_t getMaxSendSge() const {
                return max_send_sge;
            }

            /// Max number of scatter/gather elements of each workrequest in the receivequeue
            [[nodiscard]]
            constexpr uint32_t getMaxRecvSge() const {
                return max_recv_sge;
            }

            /// Maximum size of workrequests which can be posted inline in the sendqueue with Flags::INLINE in bytes
            [[nodiscard]]
            constexpr uint32_t getMaxInlineData() const {
                return max_inline_data;
            }
        };

        static_assert(sizeof(Capabilities) == sizeof(ibv_qp_cap));

        class OpenAttributes : public ibv_qp_open_attr {
            using ibv_qp_open_attr::comp_mask;
            using ibv_qp_open_attr::qp_num;
            using ibv_qp_open_attr::xrcd;
            using ibv_qp_open_attr::qp_context;
            using ibv_qp_open_attr::qp_type;
        public:
            constexpr void setCompMask(std::initializer_list<OpenAttrMask> masks) {
                uint32_t newMask = 0;
                for (auto mask : masks) {
                    newMask |= static_cast<uint32_t>(mask);
                }
                this->comp_mask = newMask;
            }

            constexpr void setQpNum(uint32_t qp_num) {
                this->qp_num = qp_num;
            }

            void setXrcd(xrcd::ExtendedConnectionDomain &xrcd) {
                this->xrcd = &xrcd;
            }

            constexpr void setQpContext(void *qp_context) {
                this->qp_context = qp_context;
            }

            constexpr void setQpType(Type qp_type) {
                this->qp_type = static_cast<ibv_qp_type>(qp_type);
            }
        };

        static_assert(sizeof(OpenAttributes) == sizeof(ibv_qp_open_attr));

        class Attributes : public ibv_qp_attr {
            using ibv_qp_attr::qp_state;
            using ibv_qp_attr::cur_qp_state;
            using ibv_qp_attr::path_mtu;
            using ibv_qp_attr::path_mig_state;
            using ibv_qp_attr::qkey;
            using ibv_qp_attr::rq_psn;
            using ibv_qp_attr::sq_psn;
            using ibv_qp_attr::dest_qp_num;
            using ibv_qp_attr::qp_access_flags;
            using ibv_qp_attr::cap;
            using ibv_qp_attr::ah_attr;
            using ibv_qp_attr::alt_ah_attr;
            using ibv_qp_attr::pkey_index;
            using ibv_qp_attr::alt_pkey_index;
            using ibv_qp_attr::en_sqd_async_notify;
            using ibv_qp_attr::sq_draining;
            using ibv_qp_attr::max_rd_atomic;
            using ibv_qp_attr::max_dest_rd_atomic;
            using ibv_qp_attr::min_rnr_timer;
            using ibv_qp_attr::port_num;
            using ibv_qp_attr::timeout;
            using ibv_qp_attr::retry_cnt;
            using ibv_qp_attr::rnr_retry;
            using ibv_qp_attr::alt_port_num;
            using ibv_qp_attr::alt_timeout;
            using ibv_qp_attr::rate_limit;
        public:
            /// The current QueuePair state
            [[nodiscard]]
            constexpr State getQpState() const {
                return static_cast<State>(qp_state);
            }

            /// Move the QueuePair to this state
            constexpr void setQpState(State qp_state) {
                this->qp_state = static_cast<ibv_qp_state>(qp_state);
            }

            /// Assume this is the current QueuePair state
            constexpr void setCurQpState(State cur_qp_state) {
                this->cur_qp_state = static_cast<ibv_qp_state>(cur_qp_state);
            }

            /// The (RC/UC) path MTU
            [[nodiscard]]
            constexpr Mtu getPathMtu() const {
                return static_cast<Mtu>(path_mtu);
            }

            /// The (RC/UC) path MTU
            constexpr void setPathMtu(Mtu path_mtu) {
                this->path_mtu = static_cast<ibv_mtu>(path_mtu);
            }

            /// Path migration state (valid if HCA supports APM)
            [[nodiscard]]
            constexpr MigrationState getPathMigState() const {
                return static_cast<MigrationState>(path_mig_state);
            }

            /// Path migration state (valid if HCA supports APM)
            constexpr void setPathMigState(MigrationState path_mig_state) {
                this->path_mig_state = static_cast<ibv_mig_state>(path_mig_state);
            }

            /// Q_Key for the QP (valid only for UD QPs)
            [[nodiscard]]
            constexpr uint32_t getQkey() const {
                return qkey;
            }

            /// Q_Key for the QP (valid only for UD QPs)
            constexpr void setQkey(uint32_t qkey) {
                this->qkey = qkey;
            }

            /// PSN for receive queue (valid only for RC/UC QPs)
            [[nodiscard]]
            constexpr uint32_t getRqPsn() const {
                return rq_psn;
            }

            /// PSN for receive queue (valid only for RC/UC QPs)
            constexpr void setRqPsn(uint32_t rq_psn) {
                this->rq_psn = rq_psn;
            }

            /// PSN for send queue (valid only for RC/UC QPs)
            [[nodiscard]]
            constexpr uint32_t getSqPsn() const {
                return sq_psn;
            }

            /// PSN for send queue (valid only for RC/UC QPs)
            constexpr void setSqPsn(uint32_t sq_psn) {
                this->sq_psn = sq_psn;
            }

            /// Destination QP number (valid only for RC/UC QPs)
            [[nodiscard]]
            constexpr uint32_t getDestQpNum() const {
                return dest_qp_num;
            }

            /// Destination QP number (valid only for RC/UC QPs)
            constexpr void setDestQpNum(uint32_t dest_qp_num) {
                this->dest_qp_num = dest_qp_num;
            }

            /// Test enabled remote access operations (valid only for RC/UC QPs)
            [[nodiscard]]
            constexpr bool hasQpAccessFlags(AccessFlag flag) const {
                const auto rawFlag = static_cast<ibv_access_flags>(flag);
                return (qp_access_flags & rawFlag) == rawFlag;
            }

            /// Set enabled remote access operations (valid only for RC/UC QPs)
            constexpr void setQpAccessFlags(std::initializer_list<AccessFlag> qp_access_flags) {
                int raw = 0;
                for (auto flag : qp_access_flags) {
                    raw |= static_cast<ibv_access_flags>(flag);
                }
                this->qp_access_flags = raw;
            }

            /// QP capabilities (valid if HCA supports QP resizing)
            [[nodiscard]]
            const Capabilities &getCap() const {
                return *reinterpret_cast<const Capabilities *>(&cap);
            }

            /// QP capabilities (valid if HCA supports QP resizing)
            constexpr void setCap(const Capabilities &cap) {
                this->cap = cap;
            }

            /// Primary path address vector (valid only for RC/UC QPs)
            [[nodiscard]]
            constexpr const ah::Attributes &getAhAttr() const {
                return *static_cast<const ah::Attributes *>(&ah_attr);
            }

            /// Primary path address vector (valid only for RC/UC QPs)
            constexpr void setAhAttr(const ah::Attributes &ah_attr) {
                this->ah_attr = ah_attr;
            }

            /// Alternate path address vector (valid only for RC/UC QPs)
            [[nodiscard]]
            constexpr const ah::Attributes &getAltAhAttr() const {
                return *static_cast<const ah::Attributes *>(&alt_ah_attr);
            }

            /// Alternate path address vector (valid only for RC/UC QPs)
            constexpr void setAltAhAttr(const ah::Attributes &alt_ah_attr) {
                this->alt_ah_attr = alt_ah_attr;
            }

            /// Primary P_Key index
            [[nodiscard]]
            constexpr uint16_t getPkeyIndex() const {
                return pkey_index;
            }

            /// Primary P_Key index
            constexpr void setPkeyIndex(uint16_t pkey_index) {
                this->pkey_index = pkey_index;
            }

            /// Alternate P_Key index
            [[nodiscard]]
            constexpr uint16_t getAltPkeyIndex() const {
                return alt_pkey_index;
            }

            /// Alternate P_Key index
            constexpr void setAltPkeyIndex(uint16_t alt_pkey_index) {
                this->alt_pkey_index = alt_pkey_index;
            }

            /// Enable SQD.drained async notification (Valid only if qp_state is SQD)
            [[nodiscard]]
            constexpr uint8_t getEnSqdAsyncNotify() const {
                return en_sqd_async_notify;
            }

            /// Enable SQD.drained async notification (Valid only if qp_state is SQD)
            constexpr void setEnSqdAsyncNotify(uint8_t en_sqd_async_notify) {
                this->en_sqd_async_notify = en_sqd_async_notify;
            }

            /// Is the QP draining? Irrelevant for ibv_modify_qp()
            [[nodiscard]]
            constexpr uint8_t getSqDraining() const {
                return sq_draining;
            }

            /// Number of outstanding RDMA reads & atomic operations on the destination QP (valid only for RC QPs)
            [[nodiscard]]
            constexpr uint8_t getMaxRdAtomic() const {
                return max_rd_atomic;
            }

            /// Number of outstanding RDMA reads & atomic operations on the destination QP (valid only for RC QPs)
            constexpr void setMaxRdAtomic(uint8_t max_rd_atomic) {
                this->max_rd_atomic = max_rd_atomic;
            }

            /// Number of responder resources for handling incoming RDMA reads & atomic operations (valid only for RC QPs)
            [[nodiscard]]
            constexpr uint8_t getMaxDestRdAtomic() const {
                return max_dest_rd_atomic;
            }

            /// Number of responder resources for handling incoming RDMA reads & atomic operations (valid only for RC QPs)
            constexpr void setMaxDestRdAtomic(uint8_t max_dest_rd_atomic) {
                this->max_dest_rd_atomic = max_dest_rd_atomic;
            }

            /// Minimum RNR NAK timer (valid only for RC QPs)
            [[nodiscard]]
            constexpr uint8_t getMinRnrTimer() const {
                return min_rnr_timer;
            }

            /// Minimum RNR NAK timer (valid only for RC QPs)
            constexpr void setMinRnrTimer(uint8_t min_rnr_timer) {
                this->min_rnr_timer = min_rnr_timer;
            }

            /// Primary port number
            [[nodiscard]]
            constexpr uint8_t getPortNum() const {
                return port_num;
            }

            /// Primary port number
            constexpr void setPortNum(uint8_t port_num) {
                this->port_num = port_num;
            }

            /// Local ack timeout for primary path (valid only for RC QPs)
            [[nodiscard]]
            constexpr uint8_t getTimeout() const {
                return timeout;
            }

            /// Local ack timeout for primary path (valid only for RC QPs)
            constexpr void setTimeout(uint8_t timeout) {
                this->timeout = timeout;
            }

            /// Retry count (valid only for RC QPs)
            [[nodiscard]]
            constexpr uint8_t getRetryCnt() const {
                return retry_cnt;
            }

            /// Retry count (valid only for RC QPs)
            constexpr void setRetryCnt(uint8_t retry_cnt) {
                this->retry_cnt = retry_cnt;
            }

            /// RNR retry (valid only for RC QPs)
            [[nodiscard]]
            constexpr uint8_t getRnrRetry() const {
                return rnr_retry;
            }

            /// RNR retry (valid only for RC QPs)
            constexpr void setRnrRetry(uint8_t rnr_retry) {
                this->rnr_retry = rnr_retry;
            }

            /// Alternate port number
            [[nodiscard]]
            constexpr uint8_t getAltPortNum() const {
                return alt_port_num;
            }

            /// Alternate port number
            constexpr void setAltPortNum(uint8_t alt_port_num) {
                this->alt_port_num = alt_port_num;
            }

            /// Local ack timeout for alternate path (valid only for RC QPs)
            [[nodiscard]]
            constexpr uint8_t getAltTimeout() const {
                return alt_timeout;
            }

            /// Local ack timeout for alternate path (valid only for RC QPs)
            constexpr void setAltTimeout(uint8_t alt_timeout) {
                this->alt_timeout = alt_timeout;
            }

            /* Only available in newer versions of verbs.h
            /// Rate limit in kbps for packet pacing
            constexpr uint32_t getRateLimit() const {
                return rate_limit;
            }

            /// Rate limit in kbps for packet pacing
            constexpr void setRateLimit(uint32_t rateLimit) {
                rate_limit = rateLimit;
            }
             */
        };

        static_assert(sizeof(Attributes) == sizeof(ibv_qp_attr));

        class InitAttributes : public ibv_qp_init_attr {
            using ibv_qp_init_attr::qp_context;
            using ibv_qp_init_attr::send_cq;
            using ibv_qp_init_attr::recv_cq;
            using ibv_qp_init_attr::srq;
            using ibv_qp_init_attr::cap;
            using ibv_qp_init_attr::qp_type;
            using ibv_qp_init_attr::sq_sig_all;
        public:
            constexpr void setContext(void *context) {
                qp_context = context;
            }

            void setSendCompletionQueue(completions::CompletionQueue &cq) {
                send_cq = &cq;
            }

            void setRecvCompletionQueue(completions::CompletionQueue &cq) {
                recv_cq = &cq;
            }

            void setSharedReceiveQueue(srq::SharedReceiveQueue &sharedReceiveQueue) {
                srq = &sharedReceiveQueue;
            }

            constexpr void setCapabilities(const Capabilities &caps) {
                cap = caps;
            }

            constexpr void setType(Type type) {
                qp_type = static_cast<ibv_qp_type>(type);
            }

            constexpr void setSignalAll(bool shouldSignal) {
                sq_sig_all = static_cast<int>(shouldSignal);
            }
        };

        static_assert(sizeof(InitAttributes) == sizeof(ibv_qp_init_attr));

        class QueuePair : public ibv_qp, public internal::PointerOnly {
            using ibv_qp::context;
            using ibv_qp::qp_context;
            using ibv_qp::pd;
            using ibv_qp::send_cq;
            using ibv_qp::recv_cq;
            using ibv_qp::srq;
            using ibv_qp::handle;
            using ibv_qp::qp_num;
            using ibv_qp::state;
            using ibv_qp::qp_type;
            using ibv_qp::mutex;
            using ibv_qp::cond;
            using ibv_qp::events_completed;
        public:
            static void *operator new(std::size_t) noexcept = delete;

            static void operator delete(void *ptr) noexcept {
                const auto status = ibv_destroy_qp(reinterpret_cast<ibv_qp *>(ptr));
                internal::checkStatusNoThrow("ibv_destroy_qp", status);
            }

            [[nodiscard]]
            constexpr uint32_t getNum() const {
                return qp_num;
            }

            /// Modify the attributes of the QueuePair, according to modifiedAttributes
            /// To get the QueuePair operational, transition the state from: Reset --> Init --> RTR --> RTS.
            /// For this transition, the following attributes must be changed:
            /// For UD QueuePairs:
            /// To Init: STATE, PKEY_INDEX, PORT, QKEY
            /// To RTR: STATE
            /// TO RTS: STATE, SQ_PSN
            /// For UC QueuePairs:
            /// To Init: STATE, PKEY_INDEX, PORT, ACCESS_FLAGS
            /// To RTR: STATE, AV, PATH_MTU
            /// To RTS: STATE, SQ_PSN
            /// For RC QueuePairs:
            /// To Init: STATE, PKEY_INDEX, PORT, ACCESS_FLAGS
            /// To RTR: STATE, AV, PATH_MTU, DEST_QPN, RQ_PSN, MAX_DEST_RD_ATOMIC, MIN_RNR_TIMER
            /// To RTS: STATE, SQ_PSN, MAX_QP_RD_ATOMIC, RETRY_CNT, RNR_RETRY, TIMEOUT
            /// For RAW_PACKET:
            /// To Init: STATE, PORT
            /// To RTR: STATE
            /// To RTS: STATE
            void modify(Attributes &attr, std::initializer_list<AttrMask> modifiedAttributes) {
                int mask = 0;
                for (auto mod : modifiedAttributes) {
                    mask |= static_cast<ibv_qp_attr_mask>(mod);
                }
                const auto status = ibv_modify_qp(this, &attr, mask);
                internal::checkStatus("ibv_modify_qp", status);
            }

            /// Get the Attributes of a QueuePair
            void query(Attributes &attr, std::initializer_list<AttrMask> queriedAttributes,
                       InitAttributes &init_attr, std::initializer_list<InitAttrMask> queriedInitAttributes) {
                int mask = 0;
                for (auto query : queriedAttributes) {
                    mask |= static_cast<ibv_qp_attr_mask>(query);
                }
                for (auto query : queriedInitAttributes) {
                    mask |= static_cast<ibv_qp_init_attr_mask>(query);
                }
                const auto status = ibv_query_qp(this, &attr, mask, &init_attr);
                internal::checkStatus("ibv_query_qp", status);
            }

            /// Get the Attributes of a QueuePair
            [[nodiscard]]
            std::tuple<Attributes, InitAttributes> query(std::initializer_list<AttrMask> queriedAttributes,
                                                         std::initializer_list<InitAttrMask> queriedInitAttributes) {
                Attributes attributes;
                InitAttributes initAttributes;
                query(attributes, queriedAttributes, initAttributes, queriedInitAttributes);
                return {attributes, initAttributes};
            }

            /// Get only the Attributes of a QueuePair
            [[nodiscard]]
            Attributes query(std::initializer_list<AttrMask> queriedAttributes) {
                auto[attributes, initAttributes] = query(queriedAttributes, {});
                std::ignore = initAttributes;
                return attributes;
            }

            /// Get only the InitAttributes of a QueuePair
            [[nodiscard]]
            InitAttributes query(std::initializer_list<InitAttrMask> queriedInitAttributes) {
                auto[attributes, initAttributes] = query({}, queriedInitAttributes);
                std::ignore = attributes;
                return initAttributes;
            }

            // TODO: custom exception instead of bad_wr
            /// Post a (possibly chained) workrequest to the send queue
            void postSend(workrequest::SendWr &wr, workrequest::SendWr *&bad_wr) {
                const auto status = ibv_post_send(this, &wr, reinterpret_cast<ibv_send_wr **>(&bad_wr));
                internal::checkStatus("ibv_post_send", status);
            }

            /// Post a (possibly chained) workrequest to the receive queue
            void postRecv(workrequest::Recv &wr, workrequest::Recv *&bad_wr) {
                const auto status = ibv_post_recv(this, &wr, reinterpret_cast<ibv_recv_wr **>(&bad_wr));
                internal::checkStatus("ibv_post_recv", status);
            }

            [[nodiscard]]
            std::unique_ptr<flow::Flow> createFlow(flow::Attributes &attr) {
                auto res = ibv_create_flow(this, &attr);
                internal::checkPtr("ibv_create_flow", res);
                return std::unique_ptr<flow::Flow>(reinterpret_cast<flow::Flow *>(res));
            }

            /// Post a request to bind a type 1 memory window to a memory region
            /// The QP Transport Service Type must be either UC, RC or XRC_SEND for bind operations
            /// @return the new rkey
            [[nodiscard]]
            uint32_t bindMemoryWindow(memorywindow::MemoryWindow &mw, memorywindow::Bind &info) {
                const auto status = ibv_bind_mw(this, &mw, &info);
                internal::checkStatus("ibv_bind_mw", status);
                return mw.getRkey();
            }

            void attachToMcastGroup(const Gid &gid, uint16_t lid) {
                const auto status = ibv_attach_mcast(this, &gid.underlying, lid);
                internal::checkStatus("ibv_attach_mcast", status);
            }

            void detachFromMcastGroup(const Gid &gid, uint16_t lid) {
                const auto status = ibv_detach_mcast(this, &gid.underlying, lid);
                internal::checkStatus("ibv_detach_mcast", status);
            }
        };

        static_assert(sizeof(QueuePair) == sizeof(ibv_qp));
    } // namespace queuepair

    namespace event {
        enum class Type : std::underlying_type_t<ibv_event_type> {
            CQ_ERR = IBV_EVENT_CQ_ERR, /// CQ is in error (CQ overrun)
            QP_FATAL = IBV_EVENT_QP_FATAL, /// Error occurred on a QP and it transitioned to error state
            QP_REQ_ERR = IBV_EVENT_QP_REQ_ERR, /// Invalid Request Local Work Queue Error
            QP_ACCESS_ERR = IBV_EVENT_QP_ACCESS_ERR, /// Local access violation error
            COMM_EST = IBV_EVENT_COMM_EST, /// Communication was established on a QP
            SQ_DRAINED = IBV_EVENT_SQ_DRAINED, /// Send Queue was drained of outstanding messages in progress
            PATH_MIG = IBV_EVENT_PATH_MIG, /// A connection has migrated to the alternate path
            PATH_MIG_ERR = IBV_EVENT_PATH_MIG_ERR, /// A connection failed to migrate to the alternate path
            DEVICE_FATAL = IBV_EVENT_DEVICE_FATAL, /// CA is in FATAL state
            PORT_ACTIVE = IBV_EVENT_PORT_ACTIVE, /// Link became active on a port
            PORT_ERR = IBV_EVENT_PORT_ERR, /// Link became unavailable on a port
            LID_CHANGE = IBV_EVENT_LID_CHANGE, /// LID was changed on a port
            PKEY_CHANGE = IBV_EVENT_PKEY_CHANGE, /// P_Key table was changed on a port
            SM_CHANGE = IBV_EVENT_SM_CHANGE, /// SM was changed on a port
            SRQ_ERR = IBV_EVENT_SRQ_ERR, /// Error occurred on an SRQ
            SRQ_LIMIT_REACHED = IBV_EVENT_SRQ_LIMIT_REACHED, /// SRQ limit was reached
            QP_LAST_WQE_REACHED = IBV_EVENT_QP_LAST_WQE_REACHED, /// Last WQE Reached on a QP associated with an SRQ
            CLIENT_REREGISTER = IBV_EVENT_CLIENT_REREGISTER, /// SM sent a CLIENT_REREGISTER request to a port
            GID_CHANGE = IBV_EVENT_GID_CHANGE /// GID table was changed on a port
        };

        enum class Cause {
            QueuePair,
            CompletionQueue,
            SharedReceiveQueue,
            Port,
            Device
        };

        class AsyncEvent : public ibv_async_event {
            using ibv_async_event::element;
            using ibv_async_event::event_type;
        public:
            [[nodiscard]]
            constexpr Type getType() const {
                return static_cast<Type>(event_type);
            }

            [[nodiscard]]
            constexpr Cause getCause() const {
                switch (getType()) {
                    case Type::QP_FATAL:
                    case Type::QP_REQ_ERR:
                    case Type::QP_ACCESS_ERR:
                    case Type::COMM_EST:
                    case Type::SQ_DRAINED:
                    case Type::PATH_MIG:
                    case Type::PATH_MIG_ERR:
                    case Type::QP_LAST_WQE_REACHED:
                        return Cause::QueuePair;
                    case Type::CQ_ERR:
                        return Cause::CompletionQueue;
                    case Type::SRQ_ERR:
                    case Type::SRQ_LIMIT_REACHED:
                        return Cause::SharedReceiveQueue;
                    case Type::PORT_ACTIVE:
                    case Type::PORT_ERR:
                    case Type::LID_CHANGE:
                    case Type::PKEY_CHANGE:
                    case Type::SM_CHANGE:
                    case Type::CLIENT_REREGISTER:
                    case Type::GID_CHANGE:
                        return Cause::Port;
                    case Type::DEVICE_FATAL:
                        return Cause::Device;
                }
            }

            [[nodiscard]]
            queuepair::QueuePair *getCausingQp() const {
                checkCause(Cause::QueuePair);
                return reinterpret_cast<queuepair::QueuePair *>(element.qp);
            }

            [[nodiscard]]
            completions::CompletionQueue *getCausingCq() const {
                checkCause(Cause::CompletionQueue);
                return reinterpret_cast<completions::CompletionQueue *>(element.cq);
            }

            [[nodiscard]]
            srq::SharedReceiveQueue *getCausingSrq() const {
                checkCause(Cause::SharedReceiveQueue);
                return reinterpret_cast<srq::SharedReceiveQueue *>(element.srq);
            }

            [[nodiscard]]
            constexpr int getCausingPort() const {
                checkCause(Cause::Port);
                return element.port_num;
            }

            void ack() {
                ibv_ack_async_event(this);
            }

        private:
            constexpr void checkCause(Cause cause) const {
                if (getCause() != cause) {
                    throw std::logic_error("Invalid event cause accessed");
                }
            }
        };

        static_assert(sizeof(AsyncEvent) == sizeof(ibv_async_event));
    } // namespace event

    namespace protectiondomain {
        class ProtectionDomain : public ibv_pd, public internal::PointerOnly {
            using ibv_pd::context;
            using ibv_pd::handle;
        public:
            static void *operator new(std::size_t) noexcept = delete;

            static void operator delete(void *ptr) noexcept {
                const auto status = ibv_dealloc_pd(reinterpret_cast<ibv_pd *>(ptr));
                internal::checkStatusNoThrow("ibv_dealloc_pd", status);
            }

            [[nodiscard]]
            context::Context *getContext() const {
                return reinterpret_cast<context::Context *>(context);
            }

            [[nodiscard]]
            constexpr uint32_t getHandle() const {
                return handle;
            }

            [[nodiscard]]
            std::unique_ptr<memoryregion::MemoryRegion>
            registerMemoryRegion(void *addr, size_t length, std::initializer_list<AccessFlag> flags) {
                using MR = memoryregion::MemoryRegion;
                int access = 0;
                for (auto flag : flags) {
                    access |= static_cast<ibv_access_flags>(flag);
                }
                const auto mr = ibv_reg_mr(this, addr, length, access);
                internal::checkPtr("ibv_reg_mr", mr);
                return std::unique_ptr<MR>(reinterpret_cast<MR *>(mr));
            }

            [[nodiscard]]
            std::unique_ptr<memorywindow::MemoryWindow>
            allocMemoryWindow(memorywindow::Type type) {
                using MW = memorywindow::MemoryWindow;
                const auto mw = ibv_alloc_mw(this, static_cast<ibv_mw_type>(type));
                internal::checkPtr("ibv_alloc_mw", mw);
                return std::unique_ptr<MW>(reinterpret_cast<MW *>(mw));
            }

            [[nodiscard]]
            std::unique_ptr<srq::SharedReceiveQueue> createSrq(srq::InitAttributes &initAttributes) {
                using SRQ = srq::SharedReceiveQueue;
                const auto srq = ibv_create_srq(this, &initAttributes);
                internal::checkPtr("ibv_create_srq", srq);
                return std::unique_ptr<SRQ>(reinterpret_cast<SRQ *>(srq));
            }

            [[nodiscard]]
            std::unique_ptr<queuepair::QueuePair> createQueuePair(queuepair::InitAttributes &initAttributes) {
                using QP = queuepair::QueuePair;
                const auto qp = ibv_create_qp(this, &initAttributes);
                internal::checkPtr("ibv_create_qp", qp);
                return std::unique_ptr<QP>(reinterpret_cast<QP *>(qp));
            }

            /// Create an AddressHandle associated with the ProtectionDomain
            [[nodiscard]]
            std::unique_ptr<ah::AddressHandle> createAddressHandle(ah::Attributes attributes) {
                using AH = ah::AddressHandle;
                const auto ah = ibv_create_ah(this, &attributes);
                internal::checkPtr("ibv_create_ah", ah);
                return std::unique_ptr<AH>(reinterpret_cast<AH *>(ah));
            }

            /// Create an AddressHandle from a work completion
            [[nodiscard]]
            std::unique_ptr<ah::AddressHandle>
            createAddressHandleFromWorkCompletion(workcompletion::WorkCompletion &wc, GlobalRoutingHeader *grh,
                                                  uint8_t port_num) {
                using AH = ah::AddressHandle;
                const auto ah = ibv_create_ah_from_wc(this, &wc, grh, port_num);
                internal::checkPtr("ibv_create_ah_from_wc", ah);
                return std::unique_ptr<AH>(reinterpret_cast<AH *>(ah));
            }
        };

        static_assert(sizeof(ProtectionDomain) == sizeof(ibv_pd));
    } // namespace protectiondomain

    namespace context {
        class Context : public ibv_context, public internal::PointerOnly {
            using ibv_context::device;
            using ibv_context::ops;
            using ibv_context::cmd_fd;
            using ibv_context::async_fd;
            using ibv_context::num_comp_vectors;
            using ibv_context::mutex;
            using ibv_context::abi_compat;
        public:
            static void *operator new(std::size_t) noexcept = delete;

            static void operator delete(void *ptr) noexcept {
                const auto status = ibv_close_device(reinterpret_cast<ibv_context *>(ptr));
                internal::checkStatusNoThrow("ibv_close_device", status);
            }

            [[nodiscard]]
            device::Device *getDevice() const {
                return reinterpret_cast<device::Device *>(device);
            }

            /// Query a device for its attributes
            [[nodiscard]]
            device::Attributes queryAttributes() {
                device::Attributes res;
                const auto status = ibv_query_device(this, &res);
                internal::checkStatus("ibv_query_device", status);
                return res;
            }

            /// query port Attributes of port port
            [[nodiscard]]
            port::Attributes queryPort(uint8_t port) {
                port::Attributes res;
                const auto status = ibv_query_port(this, port, &res);
                internal::checkStatus("ibv_query_port", status);
                return res;
            }

            /// Wait for the next async event of the device
            /// This event must be acknowledged using `event.ack()`
            [[nodiscard]]
            event::AsyncEvent getAsyncEvent() {
                event::AsyncEvent res{};
                const auto status = ibv_get_async_event(this, &res);
                internal::checkStatus("ibv_get_async_event", status);
                return res;
            }

            /// Query the Infiniband port's GID table in entry index
            [[nodiscard]]
            Gid queryGid(uint8_t port_num, int index) {
                Gid res{};
                const auto status = ibv_query_gid(this, port_num, index, &res.underlying);
                internal::checkStatus("ibv_query_gid", status);
                return res;
            }

            /// Query the Infiniband port's P_Key table in entry index
            [[nodiscard]]
            uint16_t queryPkey(uint8_t port_num, int index) {
                uint16_t res{};
                const auto status = ibv_query_pkey(this, port_num, index, &res);
                internal::checkStatus("ibv_query_pkey", status);
                return res;
            }

            /// Allocate a ProtectionDomain for the device
            [[nodiscard]]
            std::unique_ptr<protectiondomain::ProtectionDomain> allocProtectionDomain() {
                using PD = protectiondomain::ProtectionDomain;
                const auto pd = ibv_alloc_pd(this);
                internal::checkPtr("ibv_alloc_pd", pd);
                return std::unique_ptr<PD>(reinterpret_cast<PD *>(pd));
            }

            /// open an XRC protection domain
            [[nodiscard]]
            std::unique_ptr<xrcd::ExtendedConnectionDomain>
            openExtendedConnectionDomain(xrcd::InitAttributes &attr) {
                using XRCD = xrcd::ExtendedConnectionDomain;
                const auto xrcd = ibv_open_xrcd(this, &attr);
                internal::checkPtr("ibv_open_xrcd", xrcd);
                return std::unique_ptr<XRCD>(reinterpret_cast<XRCD *>(xrcd));
            }

            /// Create a completion event channel for the device
            [[nodiscard]]
            std::unique_ptr<completions::CompletionEventChannel> createCompletionEventChannel() {
                using CEC = completions::CompletionEventChannel;
                const auto compChannel = ibv_create_comp_channel(this);
                internal::checkPtr("ibv_create_comp_channel", compChannel);
                return std::unique_ptr<CEC>(reinterpret_cast<CEC *>(compChannel));
            }

            /// Create a CompletionQueue with at last cqe entries for the RDMA device
            /// @cqe - Minimum number of entries required for CQ
            /// @cq_context - Consumer-supplied context returned for completion events
            /// @channel - Completion channel where completion events will be queued.
            /// May be NULL if completion events will not be used.
            /// @comp_vector - Completion vector used to signal completion events.
            /// Must be >= 0 and < context->num_comp_vectors.
            [[nodiscard]]
            std::unique_ptr<completions::CompletionQueue>
            createCompletionQueue(int cqe, void *context, completions::CompletionEventChannel &cec,
                                  int completionVector) {
                using CQ = completions::CompletionQueue;
                const auto cq = ibv_create_cq(this, cqe, context, &cec, completionVector);
                internal::checkPtr("ibv_create_cq", cq);
                return std::unique_ptr<CQ>(reinterpret_cast<CQ *>(cq));
            }

            /// Open a shareable QueuePair
            [[nodiscard]]
            std::unique_ptr<queuepair::QueuePair> openSharableQueuePair(queuepair::OpenAttributes &openAttributes) {
                using QP = queuepair::QueuePair;
                const auto qp = ibv_open_qp(this, &openAttributes);
                internal::checkPtr("ibv_open_qp", qp);
                return std::unique_ptr<QP>(reinterpret_cast<QP *>(qp));
            }

            /// Initialize AddressHandle Attributes from a WorkCompletion wc
            /// @port_num: Port on which the received message arrived.
            /// @wc: Work completion associated with the received message.
            /// @grh: References the received global route header.  This parameter is ignored unless the work completion
            /// indicates that the GRH is valid.
            /// @ah_attr: Returned attributes that can be used when creating an address handle for replying to the
            /// message.
            void initAhAttributesFromWorkCompletion(uint8_t port_num, workcompletion::WorkCompletion &wc,
                                                    GlobalRoutingHeader *grh, ah::Attributes &attributes) {
                const auto status = ibv_init_ah_from_wc(this, port_num, &wc, grh, &attributes);
                internal::checkStatus("ibv_init_ah_from_wc", status);
            }

            /// Create new AddressHandle Attributes from a WorkCompletion
            [[nodiscard]]
            ah::Attributes getAhAttributesFromWorkCompletion(uint8_t port_num, workcompletion::WorkCompletion &wc,
                                                             GlobalRoutingHeader *grh = nullptr) {
                ah::Attributes attributes;
                initAhAttributesFromWorkCompletion(port_num, wc, grh, attributes);
                return attributes;
            }
        };
    } // namespace context

    /// Increase the 8 lsb in the given rkey
    [[nodiscard]]
    inline uint32_t incRkey(uint32_t rkey) {
        return ibv_inc_rkey(rkey);
    }

    /// Prepare data structures so that fork() may be used safely. If this function is not called or returns a non-zero
    /// status, then libibverbs data structures are not fork()-safe and the effect of an application calling fork()
    /// is undefined.
    inline void forkInit() {
        const auto status = ibv_fork_init();
        internal::checkStatus("ibv_fork_init", status);
    }
} // namespace ibv
#endif
