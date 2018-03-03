#ifndef LIBIBVERBSCPP_LIBRARY_H
#define LIBIBVERBSCPP_LIBRARY_H

#include <fcntl.h>
#include <functional>
#include <infiniband/verbs.h>
#include <initializer_list>
#include <iostream>
#include <memory>
#include <sstream>
#include <type_traits>

namespace ibv {
    // TODO: maybe replace the badWr arguments with optional return types?
    namespace {
        [[nodiscard]]
        std::runtime_error exception(const char *function, int errnum) {
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
    } // namespace

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
        REMOTE_WRITE = IBV_ACCESS_REMOTE_WRITE,
        REMOTE_READ = IBV_ACCESS_REMOTE_READ,
        REMOTE_ATOMIC = IBV_ACCESS_REMOTE_ATOMIC,
        MW_BIND = IBV_ACCESS_MW_BIND,
        ZERO_BASED = IBV_ACCESS_ZERO_BASED,
        ON_DEMAND = IBV_ACCESS_ON_DEMAND
    };

    class Gid {
        ibv_gid underlying;
    public:
        [[nodiscard]]
        constexpr uint64_t getSubnetPrefix() const {
            return underlying.global.subnet_prefix;
        }

        [[nodiscard]]
        constexpr uint64_t getInterfaceId() const {
            return underlying.global.interface_id;
        }
    };

    struct GlobalRoutingHeader : private ibv_grh {
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

    struct GlobalRoute : private ibv_global_route {
        [[nodiscard]]
        const Gid &getDgid() const {
            return *reinterpret_cast<const Gid *>(&dgid);
        }

        [[nodiscard]]
        uint32_t getFlowLabel() const {
            return flow_label;
        }

        [[nodiscard]]
        uint8_t getSgidIndex() const {
            return sgid_index;
        }

        [[nodiscard]]
        uint8_t getHopLimit() const {
            return hop_limit;
        }

        [[nodiscard]]
        uint8_t getTrafficClass() const {
            return traffic_class;
        }
    };

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

        struct Spec : private ibv_flow_spec {
            constexpr SpecType getType() const {
                return static_cast<SpecType>(hdr.type);
            }

            constexpr uint16_t getSize() const {
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
            // TODO: setters for this
        };

        struct Flow : private ibv_flow {
            Flow(const Flow &) = delete; // Can't be constructed

            static void operator delete(void *ptr) noexcept {
                const auto status = ibv_destroy_flow(reinterpret_cast<ibv_flow *>(ptr));
                checkStatusNoThrow("ibv_destroy_flow", status);
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

    namespace memorywindow {
        enum class Type : std::underlying_type_t<ibv_mw_type> {
            TYPE_1 = IBV_MW_TYPE_1,
            TYPE_2 = IBV_MW_TYPE_2
        };

        class BindInfo : ibv_mw_bind_info {
            // TODO
        };

        class Bind : ibv_mw_bind {
            // TODO
        };

        struct MemoryWindow : private ibv_mw {
            MemoryWindow(const MemoryWindow &) = delete; // Can't be constructed

            static void operator delete(void *ptr) noexcept {
                const auto status = ibv_dealloc_mw(reinterpret_cast<ibv_mw *>(ptr));
                checkStatusNoThrow("ibv_dealloc_mw", status);
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
    } // namespace memorywindow

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

        struct WorkCompletion : private ibv_wc {
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
        struct Attributes : private ibv_ah_attr {
            friend struct queuepair::Attributes;

            [[nodiscard]]
            const GlobalRoute &getGrh() const {
                return *reinterpret_cast<const GlobalRoute *>(&grh);
            }

            constexpr void setGrh(const GlobalRoute &grh) {
                this->grh = *reinterpret_cast<const ibv_global_route *>(&grh);
            }

            [[nodiscard]]
            constexpr uint16_t getDlid() const {
                return dlid;
            }

            constexpr void setDlid(uint16_t dlid) {
                this->dlid = dlid;
            }

            [[nodiscard]]
            constexpr uint8_t getSl() const {
                return sl;
            }

            constexpr void setSl(uint8_t sl) {
                this->sl = sl;
            }

            [[nodiscard]]
            constexpr uint8_t getSrcPathBits() const {
                return src_path_bits;
            }

            constexpr void setSrcPathBits(uint8_t src_path_bits) {
                this->src_path_bits = src_path_bits;
            }

            [[nodiscard]]
            constexpr uint8_t getStaticRate() const {
                return static_rate;
            }

            constexpr void setStaticRate(uint8_t static_rate) {
                this->static_rate = static_rate;
            }

            [[nodiscard]]
            constexpr bool getIsGlobal() const {
                return static_cast<bool>(is_global);
            }

            constexpr void setIsGlobal(bool is_global) {
                this->is_global = static_cast<uint8_t>(is_global);
            }

            [[nodiscard]]
            constexpr uint8_t getPortNum() const {
                return port_num;
            }

            constexpr void setPortNum(uint8_t port_num) {
                this->port_num = port_num;
            }
        };

        struct AddressHandle : private ibv_ah {
            AddressHandle(const AddressHandle &) = delete;

            static void operator delete(void *ptr) noexcept {
                const auto status = ibv_destroy_ah(reinterpret_cast<ibv_ah *>(ptr));
                checkStatusNoThrow("ibv_destroy_ah", status);
            }
        };
    } // namespace ah

    namespace completions {
        struct CompletionQueue : private ibv_cq {
            friend struct CompletionEventChannel;

            CompletionQueue(const CompletionQueue &) = delete;

            static void operator delete(void *ptr) noexcept {
                const auto status = ibv_destroy_cq(reinterpret_cast<ibv_cq *>(ptr));
                checkStatusNoThrow("ibv_destroy_cq", status);
            }

            void resize(int newCqe) {
                const auto status = ibv_resize_cq(this, newCqe);
                checkStatus("ibv_resize_cq", status);
            }

            void ackEvents(unsigned int nEvents) {
                ibv_ack_cq_events(this, nEvents);
            }

            [[nodiscard]]
            int poll(int numEntries, workcompletion::WorkCompletion *resultArray) {
                const auto res = ibv_poll_cq(this, numEntries, reinterpret_cast<ibv_wc *>(resultArray));
                check("ibv_poll_cq", res >= 0);
                return res;
            }

            void requestNotify(bool solicitedOnly) {
                const auto status = ibv_req_notify_cq(this, static_cast<int>(solicitedOnly));
                checkStatus("ibv_req_notify_cq", status);
            }
        };

        struct CompletionEventChannel : private ibv_comp_channel {
            CompletionEventChannel(const CompletionEventChannel &) = delete;

            static void operator delete(void *ptr) noexcept {
                const auto status = ibv_destroy_comp_channel(reinterpret_cast<ibv_comp_channel *>(ptr));
                checkStatusNoThrow("ibv_destroy_comp_channel", status);
            }

            [[nodiscard]]
            std::tuple<CompletionQueue *, void *> getEvent() {
                CompletionQueue *cqRet;
                void *contextRet;
                const auto status = ibv_get_cq_event(this, reinterpret_cast<ibv_cq **>(&cqRet), &contextRet);
                checkStatus("ibv_get_cq_event", status);
                return {cqRet, contextRet};
            }
        };
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

        struct Attributes : private ibv_port_attr {
            [[nodiscard]]
            constexpr State getState() const {
                return static_cast<State>(state);
            }

            [[nodiscard]]
            constexpr Mtu getMaxMtu() const {
                return static_cast<Mtu>(max_mtu);
            }

            [[nodiscard]]
            constexpr Mtu getActiveMtu() const {
                return static_cast<Mtu>(active_mtu);
            }

            [[nodiscard]]
            constexpr int getGidTblLen() const {
                return gid_tbl_len;
            }

            [[nodiscard]]
            constexpr bool hasCapability(CapabilityFlag flag) {
                const auto rawFlag = static_cast<ibv_port_cap_flags>(flag);
                return (port_cap_flags & rawFlag) == rawFlag;
            }

            [[nodiscard]]
            constexpr uint32_t getMaxMsgSize() const {
                return max_msg_sz;
            }

            [[nodiscard]]
            constexpr uint32_t getBadPkeyCntr() const {
                return bad_pkey_cntr;
            }

            [[nodiscard]]
            constexpr uint32_t getQkeyViolCntr() const {
                return qkey_viol_cntr;
            }

            [[nodiscard]]
            constexpr uint16_t getPkeyTblLen() const {
                return pkey_tbl_len;
            }

            [[nodiscard]]
            constexpr uint16_t getLid() const {
                return lid;
            }

            [[nodiscard]]
            constexpr uint16_t getSmLid() const {
                return sm_lid;
            }

            [[nodiscard]]
            constexpr uint8_t getLmc() const {
                return lmc;
            }

            [[nodiscard]]
            constexpr uint8_t getMaxVlNum() const {
                return max_vl_num;
            }

            [[nodiscard]]
            constexpr uint8_t getSmSl() const {
                return sm_sl;
            }

            [[nodiscard]]
            constexpr uint8_t getSubnetTimeout() const {
                return subnet_timeout;
            }

            [[nodiscard]]
            constexpr uint8_t getInitTypeReply() const {
                return init_type_reply;
            }

            [[nodiscard]]
            constexpr uint8_t getActiveWidth() const {
                return active_width;
            }

            [[nodiscard]]
            constexpr uint8_t getActiveSpeed() const {
                return active_speed;
            }

            [[nodiscard]]
            constexpr uint8_t getPhysState() const {
                return phys_state;
            }

            [[nodiscard]]
            constexpr uint8_t getLinkLayer() const {
                return link_layer;
            }
        };
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

        struct Attributes : private ibv_device_attr {
            [[nodiscard]]
            constexpr const char *getFwVer() const {
                return fw_ver;
            }

            [[nodiscard]]
            constexpr uint64_t getNodeGuid() const {
                return node_guid;
            }

            [[nodiscard]]
            constexpr uint64_t getSysImageGuid() const {
                return sys_image_guid;
            }

            [[nodiscard]]
            constexpr uint64_t getMaxMrSize() const {
                return max_mr_size;
            }

            [[nodiscard]]
            constexpr uint64_t getPageSizeCap() const {
                return page_size_cap;
            }

            [[nodiscard]]
            constexpr uint32_t getVendorId() const {
                return vendor_id;
            }

            [[nodiscard]]
            constexpr uint32_t getVendorPartId() const {
                return vendor_part_id;
            }

            [[nodiscard]]
            constexpr uint32_t getHwVer() const {
                return hw_ver;
            }

            [[nodiscard]]
            constexpr int getMaxQp() const {
                return max_qp;
            }

            [[nodiscard]]
            constexpr int getMaxQpWr() const {
                return max_qp_wr;
            }

            [[nodiscard]]
            constexpr bool hasCapability(CapabilityFlag flag) const {
                const auto rawFlag = static_cast<ibv_device_cap_flags>(flag);
                return (device_cap_flags & rawFlag) == rawFlag;
            }

            [[nodiscard]]
            constexpr int getMaxSge() const {
                return max_sge;
            }

            [[nodiscard]]
            constexpr int getMaxSgeRd() const {
                return max_sge_rd;
            }

            [[nodiscard]]
            constexpr int getMaxCq() const {
                return max_cq;
            }

            [[nodiscard]]
            constexpr int getMaxCqe() const {
                return max_cqe;
            }

            [[nodiscard]]
            constexpr int getMaxMr() const {
                return max_mr;
            }

            [[nodiscard]]
            constexpr int getMaxPd() const {
                return max_pd;
            }

            [[nodiscard]]
            constexpr int getMaxQpRdAtom() const {
                return max_qp_rd_atom;
            }

            [[nodiscard]]
            constexpr int getMaxEeRdAtom() const {
                return max_ee_rd_atom;
            }

            [[nodiscard]]
            constexpr int getMaxResRdAtom() const {
                return max_res_rd_atom;
            }

            [[nodiscard]]
            constexpr int getMaxQpInitRdAtom() const {
                return max_qp_init_rd_atom;
            }

            [[nodiscard]]
            constexpr int getMaxEeInitRdAtom() const {
                return max_ee_init_rd_atom;
            }

            [[nodiscard]]
            constexpr AtomicCapabilities getAtomicCap() const {
                return static_cast<AtomicCapabilities>(atomic_cap);
            }

            [[nodiscard]]
            constexpr int getMaxEe() const {
                return max_ee;
            }

            [[nodiscard]]
            constexpr int getMaxRdd() const {
                return max_rdd;
            }

            [[nodiscard]]
            constexpr int getMaxMw() const {
                return max_mw;
            }

            [[nodiscard]]
            constexpr int getMaxRawIpv6Qp() const {
                return max_raw_ipv6_qp;
            }

            [[nodiscard]]
            constexpr int getMaxRawEthyQp() const {
                return max_raw_ethy_qp;
            }

            [[nodiscard]]
            constexpr int getMaxMcastGrp() const {
                return max_mcast_grp;
            }

            [[nodiscard]]
            constexpr int getMaxMcastQpAttach() const {
                return max_mcast_qp_attach;
            }

            [[nodiscard]]
            constexpr int getMaxTotalMcastQpAttach() const {
                return max_total_mcast_qp_attach;
            }

            [[nodiscard]]
            constexpr int getMaxAh() const {
                return max_ah;
            }

            [[nodiscard]]
            constexpr int getMaxFmr() const {
                return max_fmr;
            }

            [[nodiscard]]
            constexpr int getMaxMapPerFmr() const {
                return max_map_per_fmr;
            }

            [[nodiscard]]
            constexpr int getMaxSrq() const {
                return max_srq;
            }

            [[nodiscard]]
            constexpr int getMaxSrqWr() const {
                return max_srq_wr;
            }

            [[nodiscard]]
            constexpr int getMaxSrqSge() const {
                return max_srq_sge;
            }

            [[nodiscard]]
            constexpr uint16_t getMaxPkeys() const {
                return max_pkeys;
            }

            [[nodiscard]]
            constexpr uint8_t getLocalCaAckDelay() const {
                return local_ca_ack_delay;
            }

            [[nodiscard]]
            constexpr uint8_t getPhysPortCnt() const {
                return phys_port_cnt;
            }
        };

        struct Device : private ibv_device {
            Device(const Device &) = delete;

            [[nodiscard]]
            const char *getName() {
                return ibv_get_device_name(this);
            }

            [[nodiscard]]
            uint64_t getGUID() {
                return ibv_get_device_guid(this);
            }

            [[nodiscard]]
            std::unique_ptr<context::Context> open() {
                using Ctx = context::Context;
                const auto context = ibv_open_device(this);
                checkPtr("ibv_open_device", context);
                return std::unique_ptr<Ctx>(reinterpret_cast<Ctx *>(context));
            }
        };

        class DeviceList {
            Device **devices;
            int num_devices = 0;

        public:
            DeviceList() {
                devices = reinterpret_cast<Device **>(ibv_get_device_list(&num_devices));
                checkPtr("ibv_get_device_list", devices);
            }

            ~DeviceList() {
                ibv_free_device_list(reinterpret_cast<ibv_device **>(devices));
            }

            DeviceList(const DeviceList &) = delete;

            DeviceList &operator=(DeviceList &) = delete;

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
                    return " IBV_REREG_MR_ERR_DONT_FORK_NEW";
                case ReregErrorCode::DO_FORK_OLD:
                    return " IBV_REREG_MR_ERR_DO_FORK_OLD";
                case ReregErrorCode::CMD:
                    return "IBV_REREG_MR_ERR_CMD";
                case ReregErrorCode::CMD_AND_DO_FORK_NEW:
                    return "IBV_REREG_MR_ERR_CMD_AND_DO_FORK_NEW";
            }
            __builtin_unreachable();
        }

        struct Slice : public ibv_sge {
        };

        struct MemoryRegion : private ibv_mr {
            MemoryRegion(const MemoryRegion &) = delete;

            static void operator delete(void *ptr) noexcept {
                const auto status = ibv_dereg_mr(reinterpret_cast<ibv_mr *>(ptr));
                checkStatusNoThrow("ibv_dereg_mr", status);
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

            void
            reRegister(std::initializer_list<ReregFlag> changeFlags, protectiondomain::ProtectionDomain &newPd,
                       void *newAddr, size_t newLength, std::initializer_list<AccessFlag> accessFlags) {
                int changes = 0;
                for (auto change : changeFlags) {
                    changes |= static_cast<ibv_rereg_mr_flags>(change);
                }
                int access = 0;
                for (auto accessFlag : accessFlags) {
                    access |= static_cast<ibv_access_flags>(accessFlag);
                }
                const auto status =
                        ibv_rereg_mr(this, changes, reinterpret_cast<ibv_pd *> (&newPd), newAddr, newLength, access);

                if (status != 0) {
                    const auto res = static_cast<ReregErrorCode>(status);
                    throw std::runtime_error("ibv_rereg_mr failed with: " + to_string(res));
                }
            }
        };

        [[nodiscard]]
        inline std::string to_string(const MemoryRegion &mr) {
            std::stringstream addr;
            addr << std::hex << mr.getAddr();
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
            FENCE = IBV_SEND_FENCE,
            SIGNALED = IBV_SEND_SIGNALED,
            SOLICITED = IBV_SEND_SOLICITED,
            INLINE = IBV_SEND_INLINE,
            IP_CSUM = IBV_SEND_IP_CSUM
        };

        struct SendWr : private ibv_send_wr {
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

        // internal
        struct Rdma : SendWr {
            constexpr void setRemoteAddress(uint64_t remote_addr, uint32_t rkey) { // TODO: structure for this
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
                getWr().ud.ah = reinterpret_cast<ibv_ah *>(&ah);
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
            constexpr void setRemoteAddress(uint64_t remote_addr, uint32_t rkey) { // TODO: structure for this
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

        struct Recv : private ibv_recv_wr {
            constexpr void setId(uint64_t id) {
                wr_id = id;
            }

            [[nodiscard]]
            constexpr uint64_t getId() const {
                return wr_id;
            }

            constexpr void setNext(Recv *next) {
                this->next = next;
            }

            constexpr void setSge(memoryregion::Slice *scatterGatherArray, int size) {
                sg_list = scatterGatherArray;
                num_sge = size;
            }
        };

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

        struct Attributes : private ibv_srq_attr {
            friend struct SharedReceiveQueue;

            friend struct InitAttributes;

            explicit constexpr Attributes(uint32_t max_wr = 0, uint32_t max_sge = 0, uint32_t srq_limit = 0) :
                    ibv_srq_attr{max_wr, max_sge, srq_limit} {}
        };

        struct InitAttributes : private ibv_srq_init_attr {
            explicit constexpr InitAttributes(Attributes attrs = Attributes(), void *context = nullptr) :
                    ibv_srq_init_attr{context, attrs} {}
        };

        struct SharedReceiveQueue : private ibv_srq {
            SharedReceiveQueue(const SharedReceiveQueue &) = delete;

            static void operator delete(void *ptr) noexcept {
                const auto status = ibv_destroy_srq(reinterpret_cast<ibv_srq *>(ptr));
                checkStatusNoThrow("ibv_destroy_srq", status);
            }

            void modify(Attributes &attr, std::initializer_list<AttributeMask> modifiedAttrs) {
                int modifiedMask = 0;
                for (auto mod : modifiedAttrs) {
                    modifiedMask |= static_cast<ibv_srq_attr_mask>(mod);
                }

                const auto status = ibv_modify_srq(this, &attr, modifiedMask);
                checkStatus("ibv_modify_srq", status);
            }

            void query(Attributes &res) {
                const auto status = ibv_query_srq(this, &res);
                checkStatus("ibv_query_srq", status);
            }

            [[nodiscard]]
            Attributes query() {
                Attributes res{};
                query(res);
                return res;
            }

            [[nodiscard]]
            uint32_t getNumber() {
                uint32_t num = 0;
                const auto status = ibv_get_srq_num(this, &num);
                checkStatus("ibv_get_srq_num", status);
                return num;
            }

            void postRecv(workrequest::Recv &wr, workrequest::Recv *&badWr) {
                const auto status = ibv_post_srq_recv(this, reinterpret_cast<ibv_recv_wr *>(&wr),
                                                      reinterpret_cast<ibv_recv_wr **>(&badWr));
                checkStatus("ibv_post_srq_recv", status);
            }
        };
    } // namespace srq

    namespace xrcd {
        enum class InitAttributesMask : std::underlying_type_t<ibv_xrcd_init_attr_mask> {
            FD = IBV_XRCD_INIT_ATTR_FD,
            OFLAGS = IBV_XRCD_INIT_ATTR_OFLAGS,
            RESERVED = IBV_XRCD_INIT_ATTR_RESERVED
        };

        enum class OpenFlags : int {
            CREAT = O_CREAT,
            EXCL = O_EXCL
        };

        struct InitAttributes : private ibv_xrcd_init_attr {
            constexpr void setValidComponents(std::initializer_list<InitAttributesMask> masks) {
                uint32_t newMask = 0;
                for (auto mask : masks) {
                    newMask |= static_cast<uint32_t>(mask);
                }
                this->comp_mask = newMask;
            }

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

        struct ExtendedConnectionDomain : private ibv_xrcd {
            ExtendedConnectionDomain(const ExtendedConnectionDomain &) = delete;

            static void operator delete(void *ptr) noexcept {
                const auto status = ibv_close_xrcd(reinterpret_cast<ibv_xrcd *>(ptr));
                checkStatusNoThrow("ibv_close_xrcd", status);
            }
        };
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
                    return " IBV_MIG_MIGRATED";
                case MigrationState::REARM:
                    return " IBV_MIG_REARM";
                case MigrationState::ARMED:
                    return " IBV_MIG_ARMED";
            }
            __builtin_unreachable();
        }

        struct Capabilities : public ibv_qp_cap {
            [[nodiscard]]
            constexpr uint32_t getMaxSendWr() const {
                return max_send_wr;
            }

            [[nodiscard]]
            constexpr uint32_t getMaxRecvWr() const {
                return max_recv_wr;
            }

            [[nodiscard]]
            constexpr uint32_t getMaxSendSge() const {
                return max_send_sge;
            }

            [[nodiscard]]
            constexpr uint32_t getMaxRecvSge() const {
                return max_recv_sge;
            }

            [[nodiscard]]
            constexpr uint32_t getMaxInlineData() const {
                return max_inline_data;
            }
        };

        struct OpenAttributes : private ibv_qp_open_attr {
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
                this->xrcd = reinterpret_cast<ibv_xrcd *>(&xrcd);
            }

            constexpr void setQpContext(void *qp_context) {
                this->qp_context = qp_context;
            }

            constexpr void setQpType(Type qp_type) {
                this->qp_type = static_cast<ibv_qp_type>(qp_type);
            }
        };

        struct Attributes : private ibv_qp_attr {
            friend struct QueuePair;

            [[nodiscard]]
            constexpr State getQpState() const {
                return static_cast<State>(qp_state);
            }

            constexpr void setQpState(State qp_state) {
                this->qp_state = static_cast<ibv_qp_state>(qp_state);
            }

            [[nodiscard]]
            constexpr State getCurQpState() const {
                return static_cast<State>(cur_qp_state);
            }

            constexpr void setCurQpState(State cur_qp_state) {
                this->cur_qp_state = static_cast<ibv_qp_state>(cur_qp_state);
            }

            [[nodiscard]]
            constexpr Mtu getPathMtu() const {
                return static_cast<Mtu>(path_mtu);
            }

            constexpr void setPathMtu(Mtu path_mtu) {
                this->path_mtu = static_cast<ibv_mtu>(path_mtu);
            }

            [[nodiscard]]
            constexpr MigrationState getPathMigState() const {
                return static_cast<MigrationState>(path_mig_state);
            }

            constexpr void setPathMigState(MigrationState path_mig_state) {
                this->path_mig_state = static_cast<ibv_mig_state>(path_mig_state);
            }

            [[nodiscard]]
            constexpr uint32_t getQkey() const {
                return qkey;
            }

            constexpr void setQkey(uint32_t qkey) {
                this->qkey = qkey;
            }

            [[nodiscard]]
            constexpr uint32_t getRqPsn() const {
                return rq_psn;
            }

            constexpr void setRqPsn(uint32_t rq_psn) {
                this->rq_psn = rq_psn;
            }

            [[nodiscard]]
            constexpr uint32_t getSqPsn() const {
                return sq_psn;
            }

            constexpr void setSqPsn(uint32_t sq_psn) {
                this->sq_psn = sq_psn;
            }

            [[nodiscard]]
            constexpr uint32_t getDestQpNum() const {
                return dest_qp_num;
            }

            constexpr void setDestQpNum(uint32_t dest_qp_num) {
                this->dest_qp_num = dest_qp_num;
            }

            [[nodiscard]]
            constexpr bool hasQpAccessFlags(AccessFlag flag) const {
                const auto rawFlag = static_cast<ibv_access_flags>(flag);
                return (qp_access_flags & rawFlag) == rawFlag;
            }

            constexpr void setQpAccessFlags(std::initializer_list<AccessFlag> qp_access_flags) {
                int raw = 0;
                for (auto flag : qp_access_flags) {
                    raw |= static_cast<ibv_access_flags>(flag);
                }
                this->qp_access_flags = raw;
            }

            [[nodiscard]]
            const Capabilities &getCap() const {
                return *reinterpret_cast<const Capabilities *>(&cap);
            }

            constexpr void setCap(const Capabilities &cap) {
                this->cap = cap;
            }

            [[nodiscard]]
            constexpr const ah::Attributes &getAhAttr() const {
                return *static_cast<const ah::Attributes *>(&ah_attr);
            }

            constexpr void setAhAttr(const ah::Attributes &ah_attr) {
                this->ah_attr = ah_attr;
            }

            [[nodiscard]]
            constexpr const ah::Attributes &getAltAhAttr() const {
                return *static_cast<const ah::Attributes *>(&alt_ah_attr);
            }

            constexpr void setAltAhAttr(const ah::Attributes &alt_ah_attr) {
                this->alt_ah_attr = alt_ah_attr;
            }

            [[nodiscard]]
            constexpr uint16_t getPkeyIndex() const {
                return pkey_index;
            }

            constexpr void setPkeyIndex(uint16_t pkey_index) {
                this->pkey_index = pkey_index;
            }

            [[nodiscard]]
            constexpr uint16_t getAltPkeyIndex() const {
                return alt_pkey_index;
            }

            constexpr void setAltPkeyIndex(uint16_t alt_pkey_index) {
                this->alt_pkey_index = alt_pkey_index;
            }

            [[nodiscard]]
            constexpr uint8_t getEnSqdAsyncNotify() const {
                return en_sqd_async_notify;
            }

            constexpr void setEnSqdAsyncNotify(uint8_t en_sqd_async_notify) {
                this->en_sqd_async_notify = en_sqd_async_notify;
            }

            [[nodiscard]]
            constexpr uint8_t getSqDraining() const {
                return sq_draining;
            }

            constexpr void setSqDraining(uint8_t sq_draining) {
                this->sq_draining = sq_draining;
            }

            [[nodiscard]]
            constexpr uint8_t getMaxRdAtomic() const {
                return max_rd_atomic;
            }

            constexpr void setMaxRdAtomic(uint8_t max_rd_atomic) {
                this->max_rd_atomic = max_rd_atomic;
            }

            [[nodiscard]]
            constexpr uint8_t getMaxDestRdAtomic() const {
                return max_dest_rd_atomic;
            }

            constexpr void setMaxDestRdAtomic(uint8_t max_dest_rd_atomic) {
                this->max_dest_rd_atomic = max_dest_rd_atomic;
            }

            [[nodiscard]]
            constexpr uint8_t getMinRnrTimer() const {
                return min_rnr_timer;
            }

            constexpr void setMinRnrTimer(uint8_t min_rnr_timer) {
                this->min_rnr_timer = min_rnr_timer;
            }

            [[nodiscard]]
            constexpr uint8_t getPortNum() const {
                return port_num;
            }

            constexpr void setPortNum(uint8_t port_num) {
                this->port_num = port_num;
            }

            [[nodiscard]]
            constexpr uint8_t getTimeout() const {
                return timeout;
            }

            constexpr void setTimeout(uint8_t timeout) {
                this->timeout = timeout;
            }

            [[nodiscard]]
            constexpr uint8_t getRetryCnt() const {
                return retry_cnt;
            }

            constexpr void setRetryCnt(uint8_t retry_cnt) {
                this->retry_cnt = retry_cnt;
            }

            [[nodiscard]]
            constexpr uint8_t getRnrRetry() const {
                return rnr_retry;
            }

            constexpr void setRnrRetry(uint8_t rnr_retry) {
                this->rnr_retry = rnr_retry;
            }

            [[nodiscard]]
            constexpr uint8_t getAltPortNum() const {
                return alt_port_num;
            }

            constexpr void setAltPortNum(uint8_t alt_port_num) {
                this->alt_port_num = alt_port_num;
            }

            [[nodiscard]]
            constexpr uint8_t getAltTimeout() const {
                return alt_timeout;
            }

            constexpr void setAltTimeout(uint8_t alt_timeout) {
                this->alt_timeout = alt_timeout;
            }
        };

        struct InitAttributes : private ibv_qp_init_attr {
            friend struct QueuePair;

            constexpr void setContext(void *context) {
                qp_context = context;
            }

            void setSendCompletionQueue(completions::CompletionQueue &cq) {
                send_cq = reinterpret_cast<ibv_cq *>(&cq);
            }

            void setRecvCompletionQueue(completions::CompletionQueue &cq) {
                recv_cq = reinterpret_cast<ibv_cq *>(&cq);
            }

            void setSharedReceiveQueue(srq::SharedReceiveQueue &sharedReceiveQueue) {
                srq = reinterpret_cast<ibv_srq *>(&sharedReceiveQueue);
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

        struct QueuePair : private ibv_qp {
            QueuePair(const QueuePair &) = delete;

            static void operator delete(void *ptr) noexcept {
                const auto status = ibv_destroy_qp(reinterpret_cast<ibv_qp *>(ptr));
                checkStatusNoThrow("ibv_destroy_qp", status);
            }

            [[nodiscard]]
            constexpr uint32_t getNum() const {
                return qp_num;
            }

            void modify(Attributes &attr, std::initializer_list<AttrMask> modifiedAttributes) {
                int mask = 0;
                for (auto mod : modifiedAttributes) {
                    mask |= static_cast<ibv_qp_attr_mask>(mod);
                }
                const auto status = ibv_modify_qp(this, &attr, mask);
                checkStatus("ibv_modify_qp", status);
            }

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
                checkStatus("ibv_query_qp", status);
            }

            [[nodiscard]]
            std::tuple<Attributes, InitAttributes> query(std::initializer_list<AttrMask> queriedAttributes,
                                                         std::initializer_list<InitAttrMask> queriedInitAttributes) {
                Attributes attributes;
                InitAttributes initAttributes;
                query(attributes, queriedAttributes, initAttributes, queriedInitAttributes);
                return {attributes, initAttributes};
            }

            [[nodiscard]]
            Attributes query(std::initializer_list<AttrMask> queriedAttributes) {
                auto[attributes, initAttributes] = query(queriedAttributes, {});
                std::ignore = initAttributes;
                return attributes;
            }

            [[nodiscard]]
            InitAttributes query(std::initializer_list<InitAttrMask> queriedInitAttributes) {
                auto[attributes, initAttributes] = query({}, queriedInitAttributes);
                std::ignore = attributes;
                return initAttributes;
            }

            void postSend(workrequest::SendWr &wr, workrequest::SendWr *&bad_wr) {
                const auto status = ibv_post_send(this, reinterpret_cast<ibv_send_wr *>(&wr),
                                                  reinterpret_cast<ibv_send_wr **>(&bad_wr));
                checkStatus("ibv_post_send", status);
            }

            void postRecv(workrequest::Recv &wr, workrequest::Recv *&bad_wr) {
                const auto status = ibv_post_recv(this, reinterpret_cast<ibv_recv_wr *>(&wr),
                                                  reinterpret_cast<ibv_recv_wr **>(&bad_wr));
                checkStatus("ibv_post_recv", status);
            }

            [[nodiscard]]
            std::unique_ptr<flow::Flow> createFlow(flow::Attributes &attr) {
                auto res = ibv_create_flow(this, reinterpret_cast<ibv_flow_attr *>(&attr));
                checkPtr("ibv_create_flow", res);
                return std::unique_ptr<flow::Flow>(reinterpret_cast<flow::Flow *>(res));
            }

            /// @return the new rkey
            [[nodiscard]]
            uint32_t bindMemoryWindow(memorywindow::MemoryWindow &mw, memorywindow::Bind &info) {
                const auto status = ibv_bind_mw(this, reinterpret_cast<ibv_mw *>(&mw),
                                                reinterpret_cast<ibv_mw_bind *>(&info));
                checkStatus("ibv_bind_mw", status);
                return mw.getRkey();
            }

            void attachToMcastGroup(const Gid &gid, uint16_t lid) {
                const auto status = ibv_attach_mcast(this, reinterpret_cast<const ibv_gid *>(&gid), lid);
                checkStatus("ibv_attach_mcast", status);
            }

            void detachFromMcastGroup(const Gid &gid, uint16_t lid) {
                const auto status = ibv_detach_mcast(this, reinterpret_cast<const ibv_gid *>(&gid), lid);
                checkStatus("ibv_detach_mcast", status);
            }
        };
    } // namespace queuepair

    namespace event {
        enum class Type : std::underlying_type_t<ibv_event_type> {
            CQ_ERR = IBV_EVENT_CQ_ERR,
            QP_FATAL = IBV_EVENT_QP_FATAL,
            QP_REQ_ERR = IBV_EVENT_QP_REQ_ERR,
            QP_ACCESS_ERR = IBV_EVENT_QP_ACCESS_ERR,
            COMM_EST = IBV_EVENT_COMM_EST,
            SQ_DRAINED = IBV_EVENT_SQ_DRAINED,
            PATH_MIG = IBV_EVENT_PATH_MIG,
            PATH_MIG_ERR = IBV_EVENT_PATH_MIG_ERR,
            DEVICE_FATAL = IBV_EVENT_DEVICE_FATAL,
            PORT_ACTIVE = IBV_EVENT_PORT_ACTIVE,
            PORT_ERR = IBV_EVENT_PORT_ERR,
            LID_CHANGE = IBV_EVENT_LID_CHANGE,
            PKEY_CHANGE = IBV_EVENT_PKEY_CHANGE,
            SM_CHANGE = IBV_EVENT_SM_CHANGE,
            SRQ_ERR = IBV_EVENT_SRQ_ERR,
            SRQ_LIMIT_REACHED = IBV_EVENT_SRQ_LIMIT_REACHED,
            QP_LAST_WQE_REACHED = IBV_EVENT_QP_LAST_WQE_REACHED,
            CLIENT_REREGISTER = IBV_EVENT_CLIENT_REREGISTER,
            GID_CHANGE = IBV_EVENT_GID_CHANGE
        };

        enum class Cause {
            QueuePair,
            CompletionQueue,
            SharedReceiveQueue,
            Port,
            Device
        };

        struct AsyncEvent : private ibv_async_event {

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
    } // namespace event

    namespace protectiondomain {
        struct ProtectionDomain : private ibv_pd {
            ProtectionDomain(const ProtectionDomain &) = delete;

            static void operator delete(void *ptr) noexcept {
                const auto status = ibv_dealloc_pd(reinterpret_cast<ibv_pd *>(ptr));
                checkStatusNoThrow("ibv_dealloc_pd", status);
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
                checkPtr("ibv_reg_mr", mr);
                return std::unique_ptr<MR>(reinterpret_cast<MR *>(mr));
            }

            [[nodiscard]]
            std::unique_ptr<memorywindow::MemoryWindow>
            allocMemoryWindow(memorywindow::Type type) {
                using MW = memorywindow::MemoryWindow;
                const auto mw = ibv_alloc_mw(this, static_cast<ibv_mw_type>(type));
                checkPtr("ibv_alloc_mw", mw);
                return std::unique_ptr<MW>(reinterpret_cast<MW *>(mw));
            }

            [[nodiscard]]
            std::unique_ptr<srq::SharedReceiveQueue> createSrq(srq::InitAttributes &initAttributes) {
                using SRQ = srq::SharedReceiveQueue;
                const auto srq = ibv_create_srq(this, reinterpret_cast<ibv_srq_init_attr *>(&initAttributes));
                checkPtr("ibv_create_srq", srq);
                return std::unique_ptr<SRQ>(reinterpret_cast<SRQ *>(srq));
            }

            [[nodiscard]]
            std::unique_ptr<queuepair::QueuePair> createQueuePair(queuepair::InitAttributes &initAttributes) {
                using QP = queuepair::QueuePair;
                const auto qp = ibv_create_qp(this, reinterpret_cast<ibv_qp_init_attr *>(&initAttributes));
                checkPtr("ibv_create_qp", qp);
                return std::unique_ptr<QP>(reinterpret_cast<QP *>(qp));
            }

            [[nodiscard]]
            std::unique_ptr<ah::AddressHandle> createAddressHandle(ah::Attributes attributes) {
                using AH = ah::AddressHandle;
                const auto ah = ibv_create_ah(this, reinterpret_cast<ibv_ah_attr *>(&attributes));
                checkPtr("ibv_create_ah", ah);
                return std::unique_ptr<AH>(reinterpret_cast<AH *>(ah));
            }

            [[nodiscard]]
            std::unique_ptr<ah::AddressHandle>
            createAddressHandleFromWorkCompletion(workcompletion::WorkCompletion &wc, GlobalRoutingHeader *grh,
                                                  uint8_t port_num) {
                using AH = ah::AddressHandle;
                const auto ah = ibv_create_ah_from_wc(this,
                                                      reinterpret_cast<ibv_wc *>(&wc),
                                                      reinterpret_cast<ibv_grh *>(grh),
                                                      port_num);
                checkPtr("ibv_create_ah_from_wc", ah);
                return std::unique_ptr<AH>(reinterpret_cast<AH *>(ah));
            }
        };
    } // namespace protectiondomain

    namespace context {
        struct Context : private ibv_context {
            Context(const Context &) = delete;

            static void operator delete(void *ptr) noexcept {
                const auto status = ibv_close_device(reinterpret_cast<ibv_context *>(ptr));
                checkStatusNoThrow("ibv_close_device", status);
            }

            [[nodiscard]]
            device::Device *getDevice() const {
                return reinterpret_cast<device::Device *>(device);
            }

            [[nodiscard]]
            device::Attributes queryAttributes() {
                device::Attributes res;
                const auto status = ibv_query_device(this, reinterpret_cast<ibv_device_attr *>(&res));
                checkStatus("ibv_query_device", status);
                return res;
            }

            [[nodiscard]]
            port::Attributes queryPort(uint8_t port) {
                port::Attributes res;
                const auto status = ibv_query_port(this, port, reinterpret_cast<ibv_port_attr *>(&res));
                checkStatus("ibv_query_port", status);
                return res;
            }

            [[nodiscard]]
            event::AsyncEvent getAsyncEvent() {
                event::AsyncEvent res{};
                const auto status = ibv_get_async_event(this, reinterpret_cast<ibv_async_event *>(&res));
                checkStatus("ibv_get_async_event", status);
                return res;
            }

            [[nodiscard]]
            Gid queryGid(uint8_t port_num, int index) {
                Gid res{};
                const auto status = ibv_query_gid(this, port_num, index, reinterpret_cast<ibv_gid *>(&res));
                checkStatus("ibv_query_gid", status);
                return res;
            }

            [[nodiscard]]
            uint16_t queryPkey(uint8_t port_num, int index) {
                uint16_t res{};
                const auto status = ibv_query_pkey(this, port_num, index, &res);
                checkStatus("ibv_query_pkey", status);
                return res;
            }

            [[nodiscard]]
            std::unique_ptr<protectiondomain::ProtectionDomain> allocProtectionDomain() {
                using PD = protectiondomain::ProtectionDomain;
                const auto pd = ibv_alloc_pd(this);
                checkPtr("ibv_alloc_pd", pd);
                return std::unique_ptr<PD>(reinterpret_cast<PD *>(pd));
            }

            [[nodiscard]]
            std::unique_ptr<xrcd::ExtendedConnectionDomain>
            openExtendedConnectionDomain(xrcd::InitAttributes &attr) {
                using XRCD = xrcd::ExtendedConnectionDomain;
                const auto xrcd = ibv_open_xrcd(this, reinterpret_cast<ibv_xrcd_init_attr *>(&attr));
                checkPtr("ibv_open_xrcd", xrcd);
                return std::unique_ptr<XRCD>(reinterpret_cast<XRCD *>(xrcd));
            }

            [[nodiscard]]
            std::unique_ptr<completions::CompletionEventChannel> createCompletionEventChannel() {
                using CEC = completions::CompletionEventChannel;
                const auto compChannel = ibv_create_comp_channel(this);
                checkPtr("ibv_create_comp_channel", compChannel);
                return std::unique_ptr<CEC>(reinterpret_cast<CEC *>(compChannel));
            }

            [[nodiscard]]
            std::unique_ptr<completions::CompletionQueue>
            createCompletionQueue(int cqe, void *context, completions::CompletionEventChannel &cec,
                                  int completionVector) {
                using CQ = completions::CompletionQueue;
                const auto cq = ibv_create_cq(this, cqe, context, reinterpret_cast<ibv_comp_channel *>(&cec),
                                              completionVector);
                checkPtr("ibv_create_cq", cq);
                return std::unique_ptr<CQ>(reinterpret_cast<CQ *>(cq));
            }

            [[nodiscard]]
            std::unique_ptr<queuepair::QueuePair> openSharableQueuePair(queuepair::OpenAttributes &openAttributes) {
                using QP = queuepair::QueuePair;
                const auto qp = ibv_open_qp(this, reinterpret_cast<ibv_qp_open_attr *>(&openAttributes));
                checkPtr("ibv_open_qp", qp);
                return std::unique_ptr<QP>(reinterpret_cast<QP *>(qp));
            }

            void initAhAttributesFromWorkCompletion(uint8_t port_num, workcompletion::WorkCompletion &wc,
                                                    GlobalRoutingHeader *grh, ah::Attributes &attributes) {
                const auto status = ibv_init_ah_from_wc(this, port_num, reinterpret_cast<ibv_wc *>(&wc),
                                                        reinterpret_cast<ibv_grh *>(grh),
                                                        reinterpret_cast<ibv_ah_attr *>(&attributes));
                checkStatus("ibv_init_ah_from_wc", status);
            }

            [[nodiscard]]
            ah::Attributes getAhAttributesFromWorkCompletion(uint8_t port_num, workcompletion::WorkCompletion &wc,
                                                             GlobalRoutingHeader *grh) {
                ah::Attributes attributes;
                initAhAttributesFromWorkCompletion(port_num, wc, grh, attributes);
                return attributes;
            }
        };
    } // namespace context

    [[nodiscard]]
    inline uint32_t incRkey(uint32_t rkey) {
        return ibv_inc_rkey(rkey);
    }

    inline void forkInit() {
        const auto status = ibv_fork_init();
        checkStatus("ibv_fork_init", status);
    }
} // namespace ibv
#endif
