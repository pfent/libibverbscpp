#ifndef LIBIBVERBSCPP_LIBRARY_H
#define LIBIBVERBSCPP_LIBRARY_H

#include <fcntl.h>
#include <infiniband/verbs.h>
#include <iostream>
#include <memory>
#include <sstream>

namespace ibv {
namespace internal {
[[nodiscard]] inline std::runtime_error exception(const char *function, int errnum);

constexpr void check(const char *function, bool ok);

constexpr void checkStatus(const char *function, int status);

constexpr void checkPtr(const char *function, const void *ptr);

constexpr void checkStatusNoThrow(const char *function, int status) noexcept;

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

    [[nodiscard]] constexpr uint64_t getSubnetPrefix() const;

    [[nodiscard]] constexpr uint64_t getInterfaceId() const;
};

class GlobalRoutingHeader : public ibv_grh {
    using ibv_grh::dgid;
    using ibv_grh::hop_limit;
    using ibv_grh::next_hdr;
    using ibv_grh::paylen;
    using ibv_grh::sgid;
    using ibv_grh::version_tclass_flow;

    public:
    [[nodiscard]] constexpr uint32_t getVersionTclassFlow() const;

    [[nodiscard]] constexpr uint16_t getPaylen() const;

    [[nodiscard]] constexpr uint8_t getNextHdr() const;

    [[nodiscard]] constexpr uint8_t getHopLimit() const;

    [[nodiscard]] const Gid &getSgid() const;

    [[nodiscard]] const Gid &getDgid() const;
};

static_assert(sizeof(GlobalRoutingHeader) == sizeof(ibv_grh), "");

class GlobalRoute : public ibv_global_route {
    using ibv_global_route::dgid;
    using ibv_global_route::flow_label;
    using ibv_global_route::hop_limit;
    using ibv_global_route::sgid_index;
    using ibv_global_route::traffic_class;

    public:
    /// Destination GID or MGID
    [[nodiscard]] const Gid &getDgid() const;

    /// Destination GID or MGID
    void setDgid(const Gid &dGid);

    /// Flow label
    [[nodiscard]] constexpr uint32_t getFlowLabel() const;

    /// Flow label
    constexpr void setFlowLabel(uint32_t flowLabel);

    /// Source GID index
    [[nodiscard]] constexpr uint8_t getSgidIndex() const;

    /// Source GID index
    constexpr void getSgidIndex(uint8_t sgidIndex);

    /// Hop limit
    [[nodiscard]] constexpr uint8_t getHopLimit() const;

    /// Hop limit
    constexpr void setHopLimit(uint8_t hopLimit);

    /// Traffic class
    [[nodiscard]] constexpr uint8_t getTrafficClass() const;

    /// Traffic class
    constexpr void setTrafficClass(uint8_t trafficClass);
};

static_assert(sizeof(GlobalRoute) == sizeof(ibv_global_route), "");

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
    constexpr SpecType getType() const;

    constexpr uint16_t getSize() const;
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

    static void operator delete(void *ptr) noexcept;
};
} // namespace flow

namespace context {
class Context;
} // namespace context

namespace protectiondomain {
class ProtectionDomain;
} // namespace protectiondomain

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
    using ibv_wc::byte_len;
    using ibv_wc::imm_data;
    using ibv_wc::opcode;
    using ibv_wc::status;
    using ibv_wc::vendor_err;
    using ibv_wc::wr_id;
    //            using ibv_wc::invalidated_rkey;
    using ibv_wc::dlid_path_bits;
    using ibv_wc::pkey_index;
    using ibv_wc::qp_num;
    using ibv_wc::sl;
    using ibv_wc::slid;
    using ibv_wc::src_qp;
    using ibv_wc::wc_flags;

    public:
    [[nodiscard]] constexpr uint64_t getId() const;

    [[nodiscard]] constexpr Status getStatus() const;

    [[nodiscard]] constexpr bool isSuccessful() const;

    [[nodiscard]] explicit constexpr operator bool() const;

    [[nodiscard]] constexpr Opcode getOpcode() const;

    [[nodiscard]] constexpr bool hasImmData() const;

    [[nodiscard]] constexpr bool hasInvRkey() const;

    [[nodiscard]] constexpr uint32_t getImmData() const;

    [[nodiscard]] constexpr uint32_t getInvRkey() const;

    [[nodiscard]] constexpr uint32_t getQueuePairNumber() const;

    [[nodiscard]] constexpr uint32_t getSourceQueuePair() const;

    [[nodiscard]] constexpr bool testFlag(Flag flag) const;

    [[nodiscard]] constexpr uint16_t getPkeyIndex() const;

    [[nodiscard]] constexpr uint16_t getSlid() const;

    [[nodiscard]] constexpr uint8_t getSl() const;

    [[nodiscard]] constexpr uint8_t getDlidPathBits() const;

    private:
    constexpr static void checkCondition(bool condition);
};

static_assert(sizeof(WorkCompletion) == sizeof(ibv_wc), "");

[[nodiscard]] inline std::string to_string(Opcode opcode);

[[nodiscard]] inline std::string to_string(Status status);
} // namespace workcompletion

namespace ah {
class Attributes : public ibv_ah_attr {
    using ibv_ah_attr::dlid;
    using ibv_ah_attr::grh;
    using ibv_ah_attr::is_global;
    using ibv_ah_attr::port_num;
    using ibv_ah_attr::sl;
    using ibv_ah_attr::src_path_bits;
    using ibv_ah_attr::static_rate;

    public:
    /// Global Routing Header (GRH) attributes
    [[nodiscard]] const GlobalRoute &getGrh() const;

    /// Global Routing Header (GRH) attributes
    constexpr void setGrh(const GlobalRoute &grh);

    /// Destination LID
    [[nodiscard]] constexpr uint16_t getDlid() const;

    /// Destination LID
    constexpr void setDlid(uint16_t dlid);

    /// Service Level
    [[nodiscard]] constexpr uint8_t getSl() const;

    /// Service Level
    constexpr void setSl(uint8_t sl);

    /// Source path bits
    [[nodiscard]] constexpr uint8_t getSrcPathBits() const;

    /// Source path bits
    constexpr void setSrcPathBits(uint8_t src_path_bits);

    /// Maximum static rate
    [[nodiscard]] constexpr uint8_t getStaticRate() const;

    /// Maximum static rate
    constexpr void setStaticRate(uint8_t static_rate);

    /// GRH attributes are valid
    [[nodiscard]] constexpr bool getIsGlobal() const;

    /// GRH attributes are valid
    constexpr void setIsGlobal(bool is_global);

    /// Physical port number
    [[nodiscard]] constexpr uint8_t getPortNum() const;

    /// Physical port number
    constexpr void setPortNum(uint8_t port_num);
};

static_assert(sizeof(Attributes) == sizeof(ibv_ah_attr), "");

class AddressHandle : public ibv_ah, public internal::PointerOnly {
    using ibv_ah::context;
    using ibv_ah::handle;
    using ibv_ah::pd;

    public:
    static void *operator new(std::size_t) noexcept = delete;

    static void operator delete(void *ptr) noexcept;
};

static_assert(sizeof(AddressHandle) == sizeof(ibv_ah), "");
} // namespace ah

namespace completions {
class CompletionQueue : public ibv_cq, public internal::PointerOnly {
    using ibv_cq::async_events_completed;
    using ibv_cq::channel;
    using ibv_cq::comp_events_completed;
    using ibv_cq::cond;
    using ibv_cq::context;
    using ibv_cq::cq_context;
    using ibv_cq::cqe;
    using ibv_cq::handle;
    using ibv_cq::mutex;

    public:
    static void *operator new(std::size_t) noexcept = delete;

    static void operator delete(void *ptr) noexcept;

    /// Resize the CompletionQueue to have at last newCqe entries
    void resize(int newCqe);

    /// Acknowledge nEvents events on the CompletionQueue
    void ackEvents(unsigned int nEvents);

    /// Poll the CompletionQueue for the next numEntries WorkCompletions and put them into resultArray
    /// @returns the number of completions found
    [[nodiscard]] int poll(int numEntries, workcompletion::WorkCompletion *resultArray);

    /// Request completion notification event on this CompletionQueue for the associated CompletionEventChannel
    /// @param solicitedOnly if the events should only be produced for workrequests with Flags::SOLICITED
    void requestNotify(bool solicitedOnly);
};

static_assert(sizeof(CompletionQueue) == sizeof(ibv_cq), "");

class CompletionEventChannel : public ibv_comp_channel, public internal::PointerOnly {
    using ibv_comp_channel::context;
    using ibv_comp_channel::fd;
    using ibv_comp_channel::refcnt;

    public:
    static void *operator new(std::size_t) noexcept = delete;

    static void operator delete(void *ptr) noexcept;

    /// Wait for the next completion event in this CompletionEventChannel
    /// @returns the CompletionQueue, that got the event and the CompletionQueues QP context @see setQpContext
    [[nodiscard]] std::tuple<CompletionQueue *, void *> getEvent();
};

static_assert(sizeof(CompletionEventChannel) == sizeof(ibv_comp_channel), "");
} // namespace completions

enum class Mtu : std::underlying_type_t<ibv_mtu> {
    _256 = IBV_MTU_256,
    _512 = IBV_MTU_512,
    _1024 = IBV_MTU_1024,
    _2048 = IBV_MTU_2048,
    _4096 = IBV_MTU_4096
};

[[nodiscard]] inline std::string to_string(Mtu mtu);

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
    using ibv_port_attr::active_mtu;
    using ibv_port_attr::active_speed;
    using ibv_port_attr::active_width;
    using ibv_port_attr::bad_pkey_cntr;
    using ibv_port_attr::gid_tbl_len;
    using ibv_port_attr::init_type_reply;
    using ibv_port_attr::lid;
    using ibv_port_attr::link_layer;
    using ibv_port_attr::lmc;
    using ibv_port_attr::max_msg_sz;
    using ibv_port_attr::max_mtu;
    using ibv_port_attr::max_vl_num;
    using ibv_port_attr::phys_state;
    using ibv_port_attr::pkey_tbl_len;
    using ibv_port_attr::port_cap_flags;
    using ibv_port_attr::qkey_viol_cntr;
    using ibv_port_attr::sm_lid;
    using ibv_port_attr::sm_sl;
    using ibv_port_attr::state;
    using ibv_port_attr::subnet_timeout;

    public:
    /// Logical port state
    [[nodiscard]] constexpr State getState() const;

    /// Max MTU supported by port
    [[nodiscard]] constexpr Mtu getMaxMtu() const;

    /// Actual MTU
    [[nodiscard]] constexpr Mtu getActiveMtu() const;

    /// Length of source GID table
    [[nodiscard]] constexpr int getGidTblLen() const;

    /// test port capabilities
    [[nodiscard]] constexpr bool hasCapability(CapabilityFlag flag);

    /// Maximum message size
    [[nodiscard]] constexpr uint32_t getMaxMsgSize() const;

    /// Bad P_Key counter
    [[nodiscard]] constexpr uint32_t getBadPkeyCntr() const;

    /// Q_Key violation counter
    [[nodiscard]] constexpr uint32_t getQkeyViolCntr() const;

    /// Length of partition table
    [[nodiscard]] constexpr uint16_t getPkeyTblLen() const;

    /// Base port LID
    [[nodiscard]] constexpr uint16_t getLid() const;

    /// SM LID
    [[nodiscard]] constexpr uint16_t getSmLid() const;

    /// LMC of LID
    [[nodiscard]] constexpr uint8_t getLmc() const;

    /// Maximum number of VLs
    [[nodiscard]] constexpr uint8_t getMaxVlNum() const;

    /// SM service level
    [[nodiscard]] constexpr uint8_t getSmSl() const;

    /// Subnet propagation delay
    [[nodiscard]] constexpr uint8_t getSubnetTimeout() const;

    /// Type of initialization performed by SM
    [[nodiscard]] constexpr uint8_t getInitTypeReply() const;

    /// Currently active link width
    [[nodiscard]] constexpr uint8_t getActiveWidth() const;

    /// Currently active link speed
    [[nodiscard]] constexpr uint8_t getActiveSpeed() const;

    /// Physical port state
    [[nodiscard]] constexpr uint8_t getPhysState() const;

    /// link layer protocol of the port
    [[nodiscard]] constexpr uint8_t getLinkLayer() const;
};

static_assert(sizeof(Attributes) == sizeof(ibv_port_attr), "");
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
    using ibv_device_attr::atomic_cap;
    using ibv_device_attr::device_cap_flags;
    using ibv_device_attr::fw_ver;
    using ibv_device_attr::hw_ver;
    using ibv_device_attr::local_ca_ack_delay;
    using ibv_device_attr::max_ah;
    using ibv_device_attr::max_cq;
    using ibv_device_attr::max_cqe;
    using ibv_device_attr::max_ee;
    using ibv_device_attr::max_ee_init_rd_atom;
    using ibv_device_attr::max_ee_rd_atom;
    using ibv_device_attr::max_fmr;
    using ibv_device_attr::max_map_per_fmr;
    using ibv_device_attr::max_mcast_grp;
    using ibv_device_attr::max_mcast_qp_attach;
    using ibv_device_attr::max_mr;
    using ibv_device_attr::max_mr_size;
    using ibv_device_attr::max_mw;
    using ibv_device_attr::max_pd;
    using ibv_device_attr::max_pkeys;
    using ibv_device_attr::max_qp;
    using ibv_device_attr::max_qp_init_rd_atom;
    using ibv_device_attr::max_qp_rd_atom;
    using ibv_device_attr::max_qp_wr;
    using ibv_device_attr::max_raw_ethy_qp;
    using ibv_device_attr::max_raw_ipv6_qp;
    using ibv_device_attr::max_rdd;
    using ibv_device_attr::max_res_rd_atom;
    using ibv_device_attr::max_sge;
    using ibv_device_attr::max_sge_rd;
    using ibv_device_attr::max_srq;
    using ibv_device_attr::max_srq_sge;
    using ibv_device_attr::max_srq_wr;
    using ibv_device_attr::max_total_mcast_qp_attach;
    using ibv_device_attr::node_guid;
    using ibv_device_attr::page_size_cap;
    using ibv_device_attr::phys_port_cnt;
    using ibv_device_attr::sys_image_guid;
    using ibv_device_attr::vendor_id;
    using ibv_device_attr::vendor_part_id;

    public:
    /// The Firmware verssion
    [[nodiscard]] constexpr const char *getFwVer() const;

    /// Node GUID (in network byte order)
    [[nodiscard]] constexpr uint64_t getNodeGuid() const;

    /// System image GUID (in network byte order)
    [[nodiscard]] constexpr uint64_t getSysImageGuid() const;

    /// Largest contiguous block that can be registered
    [[nodiscard]] constexpr uint64_t getMaxMrSize() const;

    /// Supported memory shift sizes
    [[nodiscard]] constexpr uint64_t getPageSizeCap() const;

    /// Vendor ID, per IEEE
    [[nodiscard]] constexpr uint32_t getVendorId() const;

    /// Vendor supplied part ID
    [[nodiscard]] constexpr uint32_t getVendorPartId() const;

    /// Hardware version
    [[nodiscard]] constexpr uint32_t getHwVer() const;

    /// Maximum number of supported QPs
    [[nodiscard]] constexpr int getMaxQp() const;

    /// Maximum number of outstanding WR on any work queue
    [[nodiscard]] constexpr int getMaxQpWr() const;

    /// Check for a capability
    [[nodiscard]] constexpr bool hasCapability(CapabilityFlag flag) const;

    /// Maximum number of s/g per WR for SQ & RQ of QP for non RDMA Read operations
    [[nodiscard]] constexpr int getMaxSge() const;

    /// Maximum number of s/g per WR for RDMA Read operations
    [[nodiscard]] constexpr int getMaxSgeRd() const;

    /// Maximum number of supported CQs
    [[nodiscard]] constexpr int getMaxCq() const;

    /// Maximum number of CQE capacity per CQ
    [[nodiscard]] constexpr int getMaxCqe() const;

    /// Maximum number of supported MRs
    [[nodiscard]] constexpr int getMaxMr() const;

    /// Maximum number of supported PDs
    [[nodiscard]] constexpr int getMaxPd() const;

    /// Maximum number of RDMA Read & Atomic operations that can be outstanding per QP
    [[nodiscard]] constexpr int getMaxQpRdAtom() const;

    /// Maximum number of RDMA Read & Atomic operations that can be outstanding per EEC
    [[nodiscard]] constexpr int getMaxEeRdAtom() const;

    /// Maximum number of resources used for RDMA Read & Atomic operations by this HCA as the Target
    [[nodiscard]] constexpr int getMaxResRdAtom() const;

    /// Maximum depth per QP for initiation of RDMA Read & Atomic operations
    [[nodiscard]] constexpr int getMaxQpInitRdAtom() const;

    /// Maximum depth per EEC for initiation of RDMA Read & Atomic operations
    [[nodiscard]] constexpr int getMaxEeInitRdAtom() const;

    /// Atomic operations support level
    [[nodiscard]] constexpr AtomicCapabilities getAtomicCap() const;

    /// Maximum number of supported EE contexts
    [[nodiscard]] constexpr int getMaxEe() const;

    /// Maximum number of supported RD domains
    [[nodiscard]] constexpr int getMaxRdd() const;

    /// Maximum number of supported MWs
    [[nodiscard]] constexpr int getMaxMw() const;

    /// Maximum number of supported raw IPv6 datagram QPs
    [[nodiscard]] constexpr int getMaxRawIpv6Qp() const;

    /// Maximum number of supported Ethertype datagram QPs
    [[nodiscard]] constexpr int getMaxRawEthyQp() const;

    /// Maximum number of supported multicast groups
    [[nodiscard]] constexpr int getMaxMcastGrp() const;

    /// Maximum number of QPs per multicast group which can be attached
    [[nodiscard]] constexpr int getMaxMcastQpAttach() const;

    /// Maximum number of QPs which can be attached to multicast groups
    [[nodiscard]] constexpr int getMaxTotalMcastQpAttach() const;

    /// Maximum number of supported address handles
    [[nodiscard]] constexpr int getMaxAh() const;

    /// Maximum number of supported FMRs
    [[nodiscard]] constexpr int getMaxFmr() const;

    /// Maximum number of (re)maps per FMR before an unmap operation in required
    [[nodiscard]] constexpr int getMaxMapPerFmr() const;

    /// Maximum number of supported SRQs
    [[nodiscard]] constexpr int getMaxSrq() const;

    /// Maximum number of WRs per SRQ
    [[nodiscard]] constexpr int getMaxSrqWr() const;

    /// Maximum number of s/g per SRQ
    [[nodiscard]] constexpr int getMaxSrqSge() const;

    /// Maximum number of partitions
    [[nodiscard]] constexpr uint16_t getMaxPkeys() const;

    /// Local CA ack delay
    [[nodiscard]] constexpr uint8_t getLocalCaAckDelay() const;

    /// Number of physical ports
    [[nodiscard]] constexpr uint8_t getPhysPortCnt() const;
};

static_assert(sizeof(Attributes) == sizeof(ibv_device_attr), "");

class Device : public ibv_device, public internal::PointerOnly {
    //            using ibv_device::_ops;
    using ibv_device::dev_name;
    using ibv_device::dev_path;
    using ibv_device::ibdev_path;
    using ibv_device::name;
    using ibv_device::node_type;
    using ibv_device::transport_type;

    public:
    /// A human-readable name associated with the RDMA device
    [[nodiscard]] const char *getName();

    /// Global Unique IDentifier (GUID) of the RDMA device
    [[nodiscard]] uint64_t getGUID();

    /// Open a RDMA device context
    [[nodiscard]] std::unique_ptr<context::Context> open();
};

static_assert(sizeof(Device) == sizeof(ibv_device), "");

class DeviceList {
    int num_devices = 0; // needs to be initialized first
    Device **devices = nullptr;

    public:
    /// Get a list of available RDMA devices
    DeviceList();

    ~DeviceList();

    DeviceList(const DeviceList &) = delete;

    DeviceList &operator=(const DeviceList &) = delete;

    DeviceList(DeviceList &&other) noexcept;

    constexpr DeviceList &operator=(DeviceList &&other) noexcept;

    [[nodiscard]] constexpr Device **begin();

    [[nodiscard]] constexpr Device **end();

    [[nodiscard]] constexpr size_t size() const;

    [[nodiscard]] constexpr Device *&operator[](int idx);
};
} // namespace device

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

[[nodiscard]] inline std::string to_string(ReregErrorCode ec);

struct Slice : public ibv_sge {
    Slice() = default;
    Slice(uint64_t addr, uint32_t length, uint32_t lkey) : ibv_sge{addr, length, lkey} {}
};

struct RemoteAddress {
    uint64_t address;
    uint32_t rkey;

    [[nodiscard]] constexpr RemoteAddress offset(uint64_t offset) const noexcept;
};

class MemoryRegion : public ibv_mr, public internal::PointerOnly {
    using ibv_mr::addr;
    using ibv_mr::context;
    using ibv_mr::handle;
    using ibv_mr::length;
    using ibv_mr::lkey;
    using ibv_mr::pd;
    using ibv_mr::rkey;

    public:
    static void *operator new(std::size_t) noexcept = delete;

    static void operator delete(void *ptr) noexcept;

    [[nodiscard]] context::Context *getContext() const;

    [[nodiscard]] protectiondomain::ProtectionDomain *getPd() const;

    [[nodiscard]] constexpr void *getAddr() const;

    [[nodiscard]] constexpr size_t getLength() const;

    [[nodiscard]] constexpr uint32_t getHandle() const;

    [[nodiscard]] constexpr uint32_t getLkey() const;

    [[nodiscard]] constexpr uint32_t getRkey() const;

    [[nodiscard]] Slice getSlice();

    [[nodiscard]] Slice getSlice(uint32_t offset, uint32_t sliceLength);

    [[nodiscard]] RemoteAddress getRemoteAddress();

    /// Reregister the MemoryRegion to modify the attribotes of an existing MemoryRegion,
    /// reusing resources whenever possible
    void reRegister(std::initializer_list<ReregFlag> changeFlags, protectiondomain::ProtectionDomain *newPd,
                    void *newAddr, size_t newLength, std::initializer_list<AccessFlag> accessFlags);
};

static_assert(sizeof(MemoryRegion) == sizeof(ibv_mr), "");

[[nodiscard]] inline std::string to_string(const MemoryRegion &mr);
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
    using ibv_send_wr::imm_data;
    using ibv_send_wr::next;
    using ibv_send_wr::num_sge;
    using ibv_send_wr::opcode;
    using ibv_send_wr::send_flags;
    using ibv_send_wr::sg_list;
    using ibv_send_wr::wr_id;
    //            using ibv_send_wr::invalidate_rkey;
    using ibv_send_wr::bind_mw;
    using ibv_send_wr::qp_type;
    using ibv_send_wr::wr;
    //            using ibv_send_wr::tso;
    public:
    constexpr SendWr();

    /// A user defined Identifier
    constexpr void setId(uint64_t id);

    /// A user defined Identifier
    [[nodiscard]] constexpr uint64_t getId() const;

    /// Pointer to the next WorkRequest. nullptr if last
    constexpr void setNext(SendWr *wrList);

    /// Set the scatter / gather array
    constexpr void setSge(memoryregion::Slice *scatterGatherArray, int size);

    /// Set a single flag specifying the work request properties
    constexpr void setFlag(Flags flag);

    constexpr void setFence();

    constexpr void setSignaled();

    constexpr void setSolicited();

    constexpr void setInline();

    constexpr void setIpCsum();

    /// Set multiple flags specifying the work request properties
    constexpr void setFlags(std::initializer_list<Flags> flags);

    protected:
    constexpr void setOpcode(Opcode opcode);

    /// Set Immediate data for this workrequest
    constexpr void setImmData(uint32_t data);

    [[nodiscard]] constexpr decltype(wr) &getWr();
};

static_assert(sizeof(SendWr) == sizeof(ibv_send_wr), "");

// internal
struct Rdma : SendWr {
    /// Set the RemoteAddress, this operation should work on
    constexpr void setRemoteAddress(memoryregion::RemoteAddress remoteAddress);

    [[deprecated]] constexpr void setRemoteAddress(uint64_t remote_addr, uint32_t rkey);
};

struct Write : Rdma {
    constexpr Write();
};

struct WriteWithImm : Write {
    constexpr WriteWithImm();

    using SendWr::setImmData;
};

struct Send : SendWr {
    constexpr Send();

    /// Address handle for the remote node address
    constexpr void setUDAddressHandle(ah::AddressHandle &ah);

    /// QueuePair number and QKey of the destination QueuePair
    constexpr void setUDRemoteQueue(uint32_t qpn, uint32_t qkey);
};

struct SendWithImm : SendWr {
    constexpr SendWithImm();

    using SendWr::setImmData;
};

struct Read : Rdma {
    constexpr Read();
};

// internal
struct Atomic : SendWr {
    /// Set the RemoteAddress, this operation should work on
    constexpr void setRemoteAddress(memoryregion::RemoteAddress remoteAddress);

    [[deprecated]] constexpr void setRemoteAddress(uint64_t remote_addr, uint32_t rkey);
};

struct AtomicCompareSwap : Atomic {
    constexpr AtomicCompareSwap();

    constexpr AtomicCompareSwap(uint64_t compare, uint64_t swap);

    /// Compare operand
    constexpr void setCompareValue(uint64_t value);

    /// Swap operand
    constexpr void setSwapValue(uint64_t value);
};

struct AtomicFetchAdd : Atomic {
    constexpr AtomicFetchAdd();

    explicit constexpr AtomicFetchAdd(uint64_t value);

    /// Add operand
    constexpr void setAddValue(uint64_t value);
};

class Recv : public ibv_recv_wr {
    using ibv_recv_wr::next;
    using ibv_recv_wr::num_sge;
    using ibv_recv_wr::sg_list;
    using ibv_recv_wr::wr_id;

    public:
    /// User defined WR ID
    constexpr void setId(uint64_t id);

    /// User defined WR ID
    [[nodiscard]] constexpr uint64_t getId() const;

    /// Pointer to next WR in list, NULL if last WR
    constexpr void setNext(Recv *next);

    /// The Scatter/Gather array with size
    constexpr void setSge(memoryregion::Slice *scatterGatherArray, int size);
};

static_assert(sizeof(Recv) == sizeof(ibv_recv_wr), "");

/// Helper class for simple workrequests, that only use a single Scatter/Gather entry, aka only write to
/// continuous memory
template <class SendWorkRequest>
class Simple : public SendWorkRequest {
    static_assert(std::is_base_of<SendWr, SendWorkRequest>::value or
                      std::is_base_of<Recv, SendWorkRequest>::value,
                  "");

    memoryregion::Slice slice{};

    public:
    using SendWorkRequest::SendWorkRequest;

    /// Set the local address, the workrequest should operate on
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
    using ibv_mw_bind_info::addr;
    using ibv_mw_bind_info::length;
    using ibv_mw_bind_info::mr;
    using ibv_mw_bind_info::mw_access_flags;

    public:
    /// The MR to bind the MW to
    constexpr void setMr(memoryregion::MemoryRegion &memoryregion);

    /// The address the MW should start at
    constexpr void setAddr(uint64_t addr);

    /// The length (in bytes) the MW should span
    constexpr void setLength(uint64_t length);

    /// Access flags to the MW
    constexpr void setMwAccessFlags(std::initializer_list<AccessFlag> accessFlags);
};

static_assert(sizeof(BindInfo) == sizeof(ibv_mw_bind_info), "");

class Bind : public ibv_mw_bind {
    using ibv_mw_bind::bind_info;
    using ibv_mw_bind::send_flags;
    using ibv_mw_bind::wr_id;

    public:
    /// User defined WR ID
    constexpr void setWrId(uint64_t id);

    // The send flags for the bind request
    constexpr void setSendFlags(std::initializer_list<workrequest::Flags> flags);

    /// MW bind information
    [[nodiscard]] BindInfo &getBindInfo();
};

static_assert(sizeof(Bind) == sizeof(ibv_mw_bind), "");

class MemoryWindow : public ibv_mw, public internal::PointerOnly {
    using ibv_mw::context;
    using ibv_mw::handle;
    using ibv_mw::pd;
    using ibv_mw::rkey;
    using ibv_mw::type;

    public:
    static void *operator new(std::size_t) noexcept = delete;

    static void operator delete(void *ptr) noexcept;

    [[nodiscard]] context::Context *getContext() const;

    [[nodiscard]] protectiondomain::ProtectionDomain *getPd() const;

    [[nodiscard]] constexpr uint32_t getRkey() const;

    [[nodiscard]] constexpr uint32_t getHandle() const;

    [[nodiscard]] constexpr Type getType();
};

static_assert(sizeof(MemoryWindow) == sizeof(ibv_mw), "");
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
    using ibv_srq_attr::max_sge;
    using ibv_srq_attr::max_wr;
    using ibv_srq_attr::srq_limit;

    public:
    explicit constexpr Attributes(uint32_t max_wr = 0, uint32_t max_sge = 0, uint32_t srq_limit = 0);
};

static_assert(sizeof(Attributes) == sizeof(ibv_srq_attr), "");

class InitAttributes : public ibv_srq_init_attr {
    using ibv_srq_init_attr::attr;
    using ibv_srq_init_attr::srq_context;

    public:
    explicit constexpr InitAttributes(Attributes attrs = Attributes(), void *context = nullptr);
};

static_assert(sizeof(InitAttributes) == sizeof(ibv_srq_init_attr), "");

class SharedReceiveQueue : public ibv_srq, public internal::PointerOnly {
    using ibv_srq::cond;
    using ibv_srq::context;
    using ibv_srq::events_completed;
    using ibv_srq::handle;
    using ibv_srq::mutex;
    using ibv_srq::pd;
    using ibv_srq::srq_context;

    public:
    static void *operator new(std::size_t) noexcept = delete;

    static void operator delete(void *ptr) noexcept;

    /// Modify the attributes of the SharedReceiveQueue. Which attributes are specified in modifiedAttrs
    void modify(Attributes &attr, std::initializer_list<AttributeMask> modifiedAttrs);

    /// Query the current attributes of the SharedReceiveQueue and return them in res
    void query(Attributes &res);

    /// Query the current attributes of the SharedReceiveQueue
    [[nodiscard]] Attributes query();

    /// Query the associated SRQ number
    [[nodiscard]] uint32_t getNumber();

    /// Post Recv workrequests to this SharedReceiveQueue, which can possibly be chained
    /// might throw and set the causing workrequest in badWr
    void postRecv(workrequest::Recv &wr, workrequest::Recv *&badWr);
};

static_assert(sizeof(SharedReceiveQueue) == sizeof(ibv_srq), "");
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
    constexpr void setValidComponents(std::initializer_list<InitAttributesMask> masks);

    /// If fd equals -1, no inode is associated with the XRCD
    constexpr void setFd(int fd);

    constexpr void setOflags(std::initializer_list<OpenFlags> oflags);
};

static_assert(sizeof(InitAttributes) == sizeof(ibv_xrcd_init_attr), "");

class ExtendedConnectionDomain : public ibv_xrcd, public internal::PointerOnly {
    using ibv_xrcd::context;

    public:
    static void *operator new(std::size_t) noexcept = delete;

    static void operator delete(void *ptr) noexcept;
};

static_assert(sizeof(ExtendedConnectionDomain) == sizeof(ibv_xrcd), "");
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

[[nodiscard]] inline std::string to_string(State state);

enum class MigrationState : std::underlying_type_t<ibv_mig_state> {
    MIGRATED = IBV_MIG_MIGRATED,
    REARM = IBV_MIG_REARM,
    ARMED = IBV_MIG_ARMED
};

[[nodiscard]] inline std::string to_string(MigrationState ms);

class Capabilities : public ibv_qp_cap { // TODO
    //using ibv_qp_cap::max_send_wr;
    //using ibv_qp_cap::max_recv_wr;
    //using ibv_qp_cap::max_send_sge;
    //using ibv_qp_cap::max_recv_sge;
    //using ibv_qp_cap::max_inline_data;
    public:
    /// Max number of outstanding workrequests in the sendqueue
    [[nodiscard]] constexpr uint32_t getMaxSendWr() const;

    /// Max number of outstanding workrequests in the receivequeue
    [[nodiscard]] constexpr uint32_t getMaxRecvWr() const;

    /// Max number of scatter/gather elements of each workrequest in the sendqueue
    [[nodiscard]] constexpr uint32_t getMaxSendSge() const;

    /// Max number of scatter/gather elements of each workrequest in the receivequeue
    [[nodiscard]] constexpr uint32_t getMaxRecvSge() const;

    /// Maximum size of workrequests which can be posted inline in the sendqueue with Flags::INLINE in bytes
    [[nodiscard]] constexpr uint32_t getMaxInlineData() const;
};

static_assert(sizeof(Capabilities) == sizeof(ibv_qp_cap), "");

class OpenAttributes : public ibv_qp_open_attr {
    using ibv_qp_open_attr::comp_mask;
    using ibv_qp_open_attr::qp_context;
    using ibv_qp_open_attr::qp_num;
    using ibv_qp_open_attr::qp_type;
    using ibv_qp_open_attr::xrcd;

    public:
    constexpr void setCompMask(std::initializer_list<OpenAttrMask> masks);

    constexpr void setQpNum(uint32_t qp_num);

    constexpr void setXrcd(xrcd::ExtendedConnectionDomain &xrcd);

    constexpr void setQpContext(void *qp_context);

    constexpr void setQpType(Type qp_type);
};

static_assert(sizeof(OpenAttributes) == sizeof(ibv_qp_open_attr), "");

class Attributes : public ibv_qp_attr {
    using ibv_qp_attr::ah_attr;
    using ibv_qp_attr::alt_ah_attr;
    using ibv_qp_attr::alt_pkey_index;
    using ibv_qp_attr::alt_port_num;
    using ibv_qp_attr::alt_timeout;
    using ibv_qp_attr::cap;
    using ibv_qp_attr::cur_qp_state;
    using ibv_qp_attr::dest_qp_num;
    using ibv_qp_attr::en_sqd_async_notify;
    using ibv_qp_attr::max_dest_rd_atomic;
    using ibv_qp_attr::max_rd_atomic;
    using ibv_qp_attr::min_rnr_timer;
    using ibv_qp_attr::path_mig_state;
    using ibv_qp_attr::path_mtu;
    using ibv_qp_attr::pkey_index;
    using ibv_qp_attr::port_num;
    using ibv_qp_attr::qkey;
    using ibv_qp_attr::qp_access_flags;
    using ibv_qp_attr::qp_state;
    using ibv_qp_attr::retry_cnt;
    using ibv_qp_attr::rnr_retry;
    using ibv_qp_attr::rq_psn;
    using ibv_qp_attr::sq_draining;
    using ibv_qp_attr::sq_psn;
    using ibv_qp_attr::timeout;
    //            using ibv_qp_attr::rate_limit;
    public:
    /// The current QueuePair state
    [[nodiscard]] constexpr State getQpState() const;

    /// Move the QueuePair to this state
    constexpr void setQpState(State qp_state);

    /// Assume this is the current QueuePair state
    constexpr void setCurQpState(State cur_qp_state);

    /// The (RC/UC) path MTU
    [[nodiscard]] constexpr Mtu getPathMtu() const;

    /// The (RC/UC) path MTU
    constexpr void setPathMtu(Mtu path_mtu);

    /// Path migration state (valid if HCA supports APM)
    [[nodiscard]] constexpr MigrationState getPathMigState() const;

    /// Path migration state (valid if HCA supports APM)
    constexpr void setPathMigState(MigrationState path_mig_state);

    /// Q_Key for the QP (valid only for UD QPs)
    [[nodiscard]] constexpr uint32_t getQkey() const;

    /// Q_Key for the QP (valid only for UD QPs)
    constexpr void setQkey(uint32_t qkey);

    /// PSN for receive queue (valid only for RC/UC QPs)
    [[nodiscard]] constexpr uint32_t getRqPsn() const;

    /// PSN for receive queue (valid only for RC/UC QPs)
    constexpr void setRqPsn(uint32_t rq_psn);

    /// PSN for send queue (valid only for RC/UC QPs)
    [[nodiscard]] constexpr uint32_t getSqPsn() const;

    /// PSN for send queue (valid only for RC/UC QPs)
    constexpr void setSqPsn(uint32_t sq_psn);

    /// Destination QP number (valid only for RC/UC QPs)
    [[nodiscard]] constexpr uint32_t getDestQpNum() const;

    /// Destination QP number (valid only for RC/UC QPs)
    constexpr void setDestQpNum(uint32_t dest_qp_num);

    /// Test enabled remote access operations (valid only for RC/UC QPs)
    [[nodiscard]] constexpr bool hasQpAccessFlags(AccessFlag flag) const;

    /// Set enabled remote access operations (valid only for RC/UC QPs)
    constexpr void setQpAccessFlags(std::initializer_list<AccessFlag> qp_access_flags);

    /// QP capabilities (valid if HCA supports QP resizing)
    [[nodiscard]] constexpr const Capabilities &getCap() const;

    /// QP capabilities (valid if HCA supports QP resizing)
    constexpr void setCap(const Capabilities &cap);

    /// Primary path address vector (valid only for RC/UC QPs)
    [[nodiscard]] constexpr const ah::Attributes &getAhAttr() const;

    /// Primary path address vector (valid only for RC/UC QPs)
    constexpr void setAhAttr(const ah::Attributes &ah_attr);

    /// Alternate path address vector (valid only for RC/UC QPs)
    [[nodiscard]] constexpr const ah::Attributes &getAltAhAttr() const;

    /// Alternate path address vector (valid only for RC/UC QPs)
    constexpr void setAltAhAttr(const ah::Attributes &alt_ah_attr);

    /// Primary P_Key index
    [[nodiscard]] constexpr uint16_t getPkeyIndex() const;

    /// Primary P_Key index
    constexpr void setPkeyIndex(uint16_t pkey_index);

    /// Alternate P_Key index
    [[nodiscard]] constexpr uint16_t getAltPkeyIndex() const;

    /// Alternate P_Key index
    constexpr void setAltPkeyIndex(uint16_t alt_pkey_index);

    /// Enable SQD.drained async notification (Valid only if qp_state is SQD)
    [[nodiscard]] constexpr uint8_t getEnSqdAsyncNotify() const;

    /// Enable SQD.drained async notification (Valid only if qp_state is SQD)
    constexpr void setEnSqdAsyncNotify(uint8_t en_sqd_async_notify);

    /// Is the QP draining? Irrelevant for ibv_modify_qp()
    [[nodiscard]] constexpr uint8_t getSqDraining() const;

    /// Number of outstanding RDMA reads & atomic operations on the destination QP (valid only for RC QPs)
    [[nodiscard]] constexpr uint8_t getMaxRdAtomic() const;

    /// Number of outstanding RDMA reads & atomic operations on the destination QP (valid only for RC QPs)
    constexpr void setMaxRdAtomic(uint8_t max_rd_atomic);

    /// Number of responder resources for handling incoming RDMA reads & atomic operations (valid only for RC QPs)
    [[nodiscard]] constexpr uint8_t getMaxDestRdAtomic() const;

    /// Number of responder resources for handling incoming RDMA reads & atomic operations (valid only for RC QPs)
    constexpr void setMaxDestRdAtomic(uint8_t max_dest_rd_atomic);

    /// Minimum RNR NAK timer (valid only for RC QPs)
    [[nodiscard]] constexpr uint8_t getMinRnrTimer() const;

    /// Minimum RNR NAK timer (valid only for RC QPs)
    constexpr void setMinRnrTimer(uint8_t min_rnr_timer);

    /// Primary port number
    [[nodiscard]] constexpr uint8_t getPortNum() const;

    /// Primary port number
    constexpr void setPortNum(uint8_t port_num);

    /// Local ack timeout for primary path (valid only for RC QPs)
    [[nodiscard]] constexpr uint8_t getTimeout() const;

    /// Local ack timeout for primary path (valid only for RC QPs)
    constexpr void setTimeout(uint8_t timeout);

    /// Retry count (valid only for RC QPs)
    [[nodiscard]] constexpr uint8_t getRetryCnt() const;

    /// Retry count (valid only for RC QPs)
    constexpr void setRetryCnt(uint8_t retry_cnt);

    /// RNR retry (valid only for RC QPs)
    [[nodiscard]] constexpr uint8_t getRnrRetry() const;

    /// RNR retry (valid only for RC QPs)
    constexpr void setRnrRetry(uint8_t rnr_retry);

    /// Alternate port number
    [[nodiscard]] constexpr uint8_t getAltPortNum() const;

    /// Alternate port number
    constexpr void setAltPortNum(uint8_t alt_port_num);

    /// Local ack timeout for alternate path (valid only for RC QPs)
    [[nodiscard]] constexpr uint8_t getAltTimeout() const;

    /// Local ack timeout for alternate path (valid only for RC QPs)
    constexpr void setAltTimeout(uint8_t alt_timeout);

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

static_assert(sizeof(Attributes) == sizeof(ibv_qp_attr), "");

class InitAttributes : public ibv_qp_init_attr {
    using ibv_qp_init_attr::cap;
    using ibv_qp_init_attr::qp_context;
    using ibv_qp_init_attr::qp_type;
    using ibv_qp_init_attr::recv_cq;
    using ibv_qp_init_attr::send_cq;
    using ibv_qp_init_attr::sq_sig_all;
    using ibv_qp_init_attr::srq;

    public:
    constexpr void setContext(void *context);

    constexpr void setSendCompletionQueue(completions::CompletionQueue &cq);

    constexpr void setRecvCompletionQueue(completions::CompletionQueue &cq);

    constexpr void setSharedReceiveQueue(srq::SharedReceiveQueue &sharedReceiveQueue);

    constexpr void setCapabilities(const Capabilities &caps);

    constexpr void setType(Type type);

    constexpr void setSignalAll(bool shouldSignal);
};

static_assert(sizeof(InitAttributes) == sizeof(ibv_qp_init_attr), "");

class QueuePair : public ibv_qp, public internal::PointerOnly {
    using ibv_qp::cond;
    using ibv_qp::context;
    using ibv_qp::events_completed;
    using ibv_qp::handle;
    using ibv_qp::mutex;
    using ibv_qp::pd;
    using ibv_qp::qp_context;
    using ibv_qp::qp_num;
    using ibv_qp::qp_type;
    using ibv_qp::recv_cq;
    using ibv_qp::send_cq;
    using ibv_qp::srq;
    using ibv_qp::state;

    public:
    static void *operator new(std::size_t) noexcept = delete;

    static void operator delete(void *ptr) noexcept;

    [[nodiscard]] constexpr uint32_t getNum() const;

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
    void modify(Attributes &attr, std::initializer_list<AttrMask> modifiedAttributes);

    /// Get the Attributes of a QueuePair
    void query(Attributes &attr, std::initializer_list<AttrMask> queriedAttributes,
               InitAttributes &init_attr, std::initializer_list<InitAttrMask> queriedInitAttributes);

    /// Get the Attributes of a QueuePair
    [[nodiscard]] std::tuple<Attributes, InitAttributes> query(std::initializer_list<AttrMask> queriedAttributes,
                                                               std::initializer_list<InitAttrMask>
                                                                   queriedInitAttributes);

    /// Get only the Attributes of a QueuePair
    [[nodiscard]] Attributes query(std::initializer_list<AttrMask> queriedAttributes);

    /// Get only the InitAttributes of a QueuePair
    [[nodiscard]] InitAttributes query(std::initializer_list<InitAttrMask> queriedInitAttributes);

    // TODO: custom exception instead of bad_wr
    /// Post a (possibly chained) workrequest to the send queue
    void postSend(workrequest::SendWr &wr, workrequest::SendWr *&bad_wr);

    /// Post a (possibly chained) workrequest to the receive queue
    void postRecv(workrequest::Recv &wr, workrequest::Recv *&bad_wr);

    [[nodiscard]] std::unique_ptr<flow::Flow> createFlow(flow::Attributes &attr);

    /// Post a request to bind a type 1 memory window to a memory region
    /// The QP Transport Service Type must be either UC, RC or XRC_SEND for bind operations
    /// @return the new rkey
    [[nodiscard]] uint32_t bindMemoryWindow(memorywindow::MemoryWindow &mw, memorywindow::Bind &info);

    void attachToMcastGroup(const Gid &gid, uint16_t lid);

    void detachFromMcastGroup(const Gid &gid, uint16_t lid);
};

static_assert(sizeof(QueuePair) == sizeof(ibv_qp), "");
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
    [[nodiscard]] constexpr Type getType() const;

    [[nodiscard]] constexpr Cause getCause() const;

    [[nodiscard]] queuepair::QueuePair *getCausingQp() const;

    [[nodiscard]] completions::CompletionQueue *getCausingCq() const;

    [[nodiscard]] srq::SharedReceiveQueue *getCausingSrq() const;

    [[nodiscard]] constexpr int getCausingPort() const;

    void ack();

    private:
    constexpr void checkCause(Cause cause) const;
};

static_assert(sizeof(AsyncEvent) == sizeof(ibv_async_event), "");
} // namespace event

namespace protectiondomain {
class ProtectionDomain : public ibv_pd, public internal::PointerOnly {
    using ibv_pd::context;
    using ibv_pd::handle;

    public:
    static void *operator new(std::size_t) noexcept = delete;

    static void operator delete(void *ptr) noexcept;

    [[nodiscard]] context::Context *getContext() const;

    [[nodiscard]] constexpr uint32_t getHandle() const;

    [[nodiscard]] std::unique_ptr<memoryregion::MemoryRegion>
    registerMemoryRegion(void *addr, size_t length, std::initializer_list<AccessFlag> flags);

    [[nodiscard]] std::unique_ptr<memorywindow::MemoryWindow>
    allocMemoryWindow(memorywindow::Type type);

    [[nodiscard]] std::unique_ptr<srq::SharedReceiveQueue> createSrq(srq::InitAttributes &initAttributes);

    [[nodiscard]] std::unique_ptr<queuepair::QueuePair> createQueuePair(queuepair::InitAttributes &initAttributes);

    /// Create an AddressHandle associated with the ProtectionDomain
    [[nodiscard]] std::unique_ptr<ah::AddressHandle> createAddressHandle(ah::Attributes attributes);

    /// Create an AddressHandle from a work completion
    [[nodiscard]] std::unique_ptr<ah::AddressHandle>
    createAddressHandleFromWorkCompletion(workcompletion::WorkCompletion &wc, GlobalRoutingHeader *grh,
                                          uint8_t port_num);
};

static_assert(sizeof(ProtectionDomain) == sizeof(ibv_pd), "");
} // namespace protectiondomain

namespace context {
class Context : public ibv_context, public internal::PointerOnly {
    using ibv_context::abi_compat;
    using ibv_context::async_fd;
    using ibv_context::cmd_fd;
    using ibv_context::device;
    using ibv_context::mutex;
    using ibv_context::num_comp_vectors;
    using ibv_context::ops;

    public:
    static void *operator new(std::size_t) noexcept = delete;

    static void operator delete(void *ptr) noexcept;

    [[nodiscard]] device::Device *getDevice() const;

    /// Query a device for its attributes
    [[nodiscard]] device::Attributes queryAttributes();

    /// query port Attributes of port port
    [[nodiscard]] port::Attributes queryPort(uint8_t port);

    /// Wait for the next async event of the device
    /// This event must be acknowledged using `event.ack()`
    [[nodiscard]] event::AsyncEvent getAsyncEvent();

    /// Query the Infiniband port's GID table in entry index
    [[nodiscard]] Gid queryGid(uint8_t port_num, int index);

    /// Query the Infiniband port's P_Key table in entry index
    [[nodiscard]] uint16_t queryPkey(uint8_t port_num, int index);

    /// Allocate a ProtectionDomain for the device
    [[nodiscard]] std::unique_ptr<protectiondomain::ProtectionDomain> allocProtectionDomain();

    /// open an XRC protection domain
    [[nodiscard]] std::unique_ptr<xrcd::ExtendedConnectionDomain>
    openExtendedConnectionDomain(xrcd::InitAttributes &attr);

    /// Create a completion event channel for the device
    [[nodiscard]] std::unique_ptr<completions::CompletionEventChannel> createCompletionEventChannel();

    /// Create a CompletionQueue with at last cqe entries for the RDMA device
    /// @cqe - Minimum number of entries required for CQ
    /// @cq_context - Consumer-supplied context returned for completion events
    /// @channel - Completion channel where completion events will be queued.
    /// May be NULL if completion events will not be used.
    /// @comp_vector - Completion vector used to signal completion events.
    /// Must be >= 0 and < context->num_comp_vectors.
    [[nodiscard]] std::unique_ptr<completions::CompletionQueue>
    createCompletionQueue(int cqe, void *context, completions::CompletionEventChannel &cec,
                          int completionVector);

    /// Open a shareable QueuePair
    [[nodiscard]] std::unique_ptr<queuepair::QueuePair> openSharableQueuePair(queuepair::OpenAttributes &openAttributes);

    /// Initialize AddressHandle Attributes from a WorkCompletion wc
    /// @port_num: Port on which the received message arrived.
    /// @wc: Work completion associated with the received message.
    /// @grh: References the received global route header.  This parameter is ignored unless the work completion
    /// indicates that the GRH is valid.
    /// @ah_attr: Returned attributes that can be used when creating an address handle for replying to the
    /// message.
    void initAhAttributesFromWorkCompletion(uint8_t port_num, workcompletion::WorkCompletion &wc,
                                            GlobalRoutingHeader *grh, ah::Attributes &attributes);

    /// Create new AddressHandle Attributes from a WorkCompletion
    [[nodiscard]] ah::Attributes getAhAttributesFromWorkCompletion(uint8_t port_num, workcompletion::WorkCompletion &wc,
                                                                   GlobalRoutingHeader *grh = nullptr);
};
} // namespace context

/// Increase the 8 lsb in the given rkey
[[nodiscard]] inline uint32_t incRkey(uint32_t rkey);

/// Prepare data structures so that fork() may be used safely. If this function is not called or returns a non-zero
/// status, then libibverbs data structures are not fork()-safe and the effect of an application calling fork()
/// is undefined.
inline void forkInit();
} // namespace ibv

/**********************************************************************************************************************/

std::runtime_error ibv::internal::exception(const char *function, int errnum) {
    return std::runtime_error(
        std::string(function) + " failed with error " + std::to_string(errnum) + ": " + strerror(errnum));
}

constexpr void ibv::internal::check(const char *function, bool ok) {
    if (not ok) {
        throw exception(function, errno);
    }
}

constexpr void ibv::internal::checkStatus(const char *function, int status) {
    if (status != 0) {
        throw exception(function, status);
    }
}

constexpr void ibv::internal::checkPtr(const char *function, const void *ptr) {
    if (ptr == nullptr) {
        throw exception(function, errno);
    }
}

constexpr void ibv::internal::checkStatusNoThrow(const char *function, int status) noexcept {
    if (status != 0) {
        std::clog << function << " failed with error " << std::to_string(status) << ": " << strerror(status);
    }
}

constexpr uint64_t ibv::Gid::getSubnetPrefix() const {
    return underlying.global.subnet_prefix;
}

constexpr uint64_t ibv::Gid::getInterfaceId() const {
    return underlying.global.interface_id;
}

constexpr uint16_t ibv::GlobalRoutingHeader::getPaylen() const {
    return paylen;
}

constexpr uint32_t ibv::GlobalRoutingHeader::getVersionTclassFlow() const {
    return version_tclass_flow;
}

constexpr uint8_t ibv::GlobalRoutingHeader::getNextHdr() const {
    return next_hdr;
}

constexpr uint8_t ibv::GlobalRoutingHeader::getHopLimit() const {
    return hop_limit;
}

inline const ibv::Gid &ibv::GlobalRoutingHeader::getSgid() const {
    return *reinterpret_cast<const Gid *>(&sgid);
}

inline const ibv::Gid &ibv::GlobalRoutingHeader::getDgid() const {
    return *reinterpret_cast<const Gid *>(&dgid);
}

inline const ibv::Gid &ibv::GlobalRoute::getDgid() const {
    return *reinterpret_cast<const Gid *>(&dgid);
}

constexpr uint32_t ibv::GlobalRoute::getFlowLabel() const {
    return flow_label;
}

constexpr uint8_t ibv::GlobalRoute::getSgidIndex() const {
    return sgid_index;
}

constexpr uint8_t ibv::GlobalRoute::getHopLimit() const {
    return hop_limit;
}

constexpr uint8_t ibv::GlobalRoute::getTrafficClass() const {
    return traffic_class;
}

inline void ibv::GlobalRoute::setDgid(const Gid &gid) {
    dgid = *reinterpret_cast<const ibv_gid *>(&gid);
}

constexpr void ibv::GlobalRoute::setFlowLabel(uint32_t flowLabel) {
    flow_label = flowLabel;
}

constexpr void ibv::GlobalRoute::getSgidIndex(uint8_t sgidIndex) {
    sgid_index = sgidIndex;
}

constexpr void ibv::GlobalRoute::setHopLimit(uint8_t hopLimit) {
    hop_limit = hopLimit;
}

constexpr void ibv::GlobalRoute::setTrafficClass(uint8_t trafficClass) {
    traffic_class = trafficClass;
}

constexpr ibv::flow::SpecType ibv::flow::Spec::getType() const {
    return static_cast<SpecType>(hdr.type);
}

constexpr uint16_t ibv::flow::Spec::getSize() const {
    return hdr.size;
}

inline void ibv::flow::Flow::operator delete(void *ptr) noexcept {
    const auto status = ibv_destroy_flow(reinterpret_cast<ibv_flow *>(ptr));
    internal::checkStatusNoThrow("ibv_destroy_flow", status);
}

constexpr uint64_t ibv::workcompletion::WorkCompletion::getId() const {
    return wr_id;
}

constexpr ibv::workcompletion::Status ibv::workcompletion::WorkCompletion::getStatus() const {
    return static_cast<Status>(status);
}

constexpr bool ibv::workcompletion::WorkCompletion::isSuccessful() const {
    return getStatus() == Status::SUCCESS;
}

constexpr ibv::workcompletion::WorkCompletion::operator bool() const {
    return isSuccessful();
}

constexpr ibv::workcompletion::Opcode ibv::workcompletion::WorkCompletion::getOpcode() const {
    return static_cast<Opcode>(opcode);
}

constexpr bool ibv::workcompletion::WorkCompletion::hasImmData() const {
    return testFlag(Flag::WITH_IMM);
}

constexpr bool ibv::workcompletion::WorkCompletion::hasInvRkey() const {
    return testFlag(Flag::WITH_INV);
}

constexpr uint32_t ibv::workcompletion::WorkCompletion::getImmData() const {
    checkCondition(hasImmData());
    return imm_data;
}

constexpr uint32_t ibv::workcompletion::WorkCompletion::getInvRkey() const {
    checkCondition(hasInvRkey());
    return imm_data;
}

constexpr uint32_t ibv::workcompletion::WorkCompletion::getQueuePairNumber() const {
    return qp_num;
}

constexpr uint32_t ibv::workcompletion::WorkCompletion::getSourceQueuePair() const {
    return src_qp;
}

constexpr bool ibv::workcompletion::WorkCompletion::testFlag(ibv::workcompletion::Flag flag) const {
    const auto rawFlag = static_cast<ibv_wc_flags>(flag);
    return (wc_flags & rawFlag) == rawFlag;
}

constexpr uint16_t ibv::workcompletion::WorkCompletion::getPkeyIndex() const {
    return pkey_index;
}

constexpr uint16_t ibv::workcompletion::WorkCompletion::getSlid() const {
    return slid;
}

constexpr uint8_t ibv::workcompletion::WorkCompletion::getSl() const {
    return sl;
}

constexpr uint8_t ibv::workcompletion::WorkCompletion::getDlidPathBits() const {
    return dlid_path_bits;
}

constexpr void ibv::workcompletion::WorkCompletion::checkCondition(bool condition) {
    if (not condition) {
        throw std::logic_error("Invalid workcompletion data access");
    }
}

std::string ibv::workcompletion::to_string(ibv::workcompletion::Opcode opcode) {
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

std::string ibv::workcompletion::to_string(ibv::workcompletion::Status status) {
    return ibv_wc_status_str(static_cast<ibv_wc_status>(status));
}

inline const ibv::GlobalRoute &ibv::ah::Attributes::getGrh() const {
    return *reinterpret_cast<const GlobalRoute *>(&grh);
}

constexpr void ibv::ah::Attributes::setGrh(const ibv::GlobalRoute &grh) {
    this->grh = grh;
}

constexpr uint16_t ibv::ah::Attributes::getDlid() const {
    return dlid;
}

constexpr void ibv::ah::Attributes::setDlid(uint16_t dlid) {
    this->dlid = dlid;
}

constexpr uint8_t ibv::ah::Attributes::getSl() const {
    return sl;
}

constexpr void ibv::ah::Attributes::setSl(uint8_t sl) {
    this->sl = sl;
}

constexpr uint8_t ibv::ah::Attributes::getSrcPathBits() const {
    return src_path_bits;
}

constexpr void ibv::ah::Attributes::setSrcPathBits(uint8_t src_path_bits) {
    this->src_path_bits = src_path_bits;
}

constexpr uint8_t ibv::ah::Attributes::getStaticRate() const {
    return static_rate;
}

constexpr void ibv::ah::Attributes::setStaticRate(uint8_t static_rate) {
    this->static_rate = static_rate;
}

constexpr bool ibv::ah::Attributes::getIsGlobal() const {
    return static_cast<bool>(is_global);
}

constexpr void ibv::ah::Attributes::setIsGlobal(bool is_global) {
    this->is_global = static_cast<uint8_t>(is_global);
}

constexpr uint8_t ibv::ah::Attributes::getPortNum() const {
    return port_num;
}

constexpr void ibv::ah::Attributes::setPortNum(uint8_t port_num) {
    this->port_num = port_num;
}

inline void ibv::ah::AddressHandle::operator delete(void *ptr) noexcept {
    const auto status = ibv_destroy_ah(reinterpret_cast<ibv_ah *>(ptr));
    internal::checkStatusNoThrow("ibv_destroy_ah", status);
}

inline void ibv::completions::CompletionQueue::operator delete(void *ptr) noexcept {
    const auto status = ibv_destroy_cq(reinterpret_cast<ibv_cq *>(ptr));
    internal::checkStatusNoThrow("ibv_destroy_cq", status);
}

inline void ibv::completions::CompletionQueue::resize(int newCqe) {
    const auto status = ibv_resize_cq(this, newCqe);
    internal::checkStatus("ibv_resize_cq", status);
}

inline void ibv::completions::CompletionQueue::ackEvents(unsigned int nEvents) {
    ibv_ack_cq_events(this, nEvents);
}

inline int ibv::completions::CompletionQueue::poll(int numEntries, ibv::workcompletion::WorkCompletion *resultArray) {
    const auto res = ibv_poll_cq(this, numEntries, resultArray);
    internal::check("ibv_poll_cq", res >= 0);
    return res;
}

inline void ibv::completions::CompletionQueue::requestNotify(bool solicitedOnly) {
    const auto status = ibv_req_notify_cq(this, static_cast<int>(solicitedOnly));
    internal::checkStatus("ibv_req_notify_cq", status);
}

inline void ibv::completions::CompletionEventChannel::operator delete(void *ptr) noexcept {
    const auto status = ibv_destroy_comp_channel(reinterpret_cast<ibv_comp_channel *>(ptr));
    internal::checkStatusNoThrow("ibv_destroy_comp_channel", status);
}

inline std::tuple<ibv::completions::CompletionQueue *, void *> ibv::completions::CompletionEventChannel::getEvent() {
    CompletionQueue *cqRet;
    void *contextRet;
    const auto status = ibv_get_cq_event(this, reinterpret_cast<ibv_cq **>(&cqRet), &contextRet);
    internal::checkStatus("ibv_get_cq_event", status);
    return {cqRet, contextRet};
}

std::string ibv::to_string(ibv::Mtu mtu) {
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

uint32_t ibv::incRkey(uint32_t rkey) {
    return ibv_inc_rkey(rkey);
}

void ibv::forkInit() {
    const auto status = ibv_fork_init();
    internal::checkStatus("ibv_fork_init", status);
}

constexpr ibv::port::State ibv::port::Attributes::getState() const {
    return static_cast<State>(state);
}

constexpr ibv::Mtu ibv::port::Attributes::getMaxMtu() const {
    return static_cast<Mtu>(max_mtu);
}

constexpr ibv::Mtu ibv::port::Attributes::getActiveMtu() const {
    return static_cast<Mtu>(active_mtu);
}

constexpr int ibv::port::Attributes::getGidTblLen() const {
    return gid_tbl_len;
}

constexpr bool ibv::port::Attributes::hasCapability(ibv::port::CapabilityFlag flag) {
    const auto rawFlag = static_cast<ibv_port_cap_flags>(flag);
    return (port_cap_flags & rawFlag) == rawFlag;
}

constexpr uint32_t ibv::port::Attributes::getMaxMsgSize() const {
    return max_msg_sz;
}

constexpr uint32_t ibv::port::Attributes::getBadPkeyCntr() const {
    return bad_pkey_cntr;
}

constexpr uint32_t ibv::port::Attributes::getQkeyViolCntr() const {
    return qkey_viol_cntr;
}

constexpr uint16_t ibv::port::Attributes::getPkeyTblLen() const {
    return pkey_tbl_len;
}

constexpr uint16_t ibv::port::Attributes::getLid() const {
    return lid;
}

constexpr uint16_t ibv::port::Attributes::getSmLid() const {
    return sm_lid;
}

constexpr uint8_t ibv::port::Attributes::getLmc() const {
    return lmc;
}

constexpr uint8_t ibv::port::Attributes::getMaxVlNum() const {
    return max_vl_num;
}

constexpr uint8_t ibv::port::Attributes::getSmSl() const {
    return sm_sl;
}

constexpr uint8_t ibv::port::Attributes::getSubnetTimeout() const {
    return subnet_timeout;
}

constexpr uint8_t ibv::port::Attributes::getInitTypeReply() const {
    return init_type_reply;
}

constexpr uint8_t ibv::port::Attributes::getActiveWidth() const {
    return active_width;
}

constexpr uint8_t ibv::port::Attributes::getActiveSpeed() const {
    return active_speed;
}

constexpr uint8_t ibv::port::Attributes::getPhysState() const {
    return phys_state;
}

constexpr uint8_t ibv::port::Attributes::getLinkLayer() const {
    return link_layer;
}

constexpr const char *ibv::device::Attributes::getFwVer() const {
    return static_cast<const char *>(fw_ver);
}

constexpr uint64_t ibv::device::Attributes::getNodeGuid() const {
    return node_guid;
}

constexpr uint64_t ibv::device::Attributes::getSysImageGuid() const {
    return sys_image_guid;
}

constexpr uint64_t ibv::device::Attributes::getMaxMrSize() const {
    return max_mr_size;
}

constexpr uint64_t ibv::device::Attributes::getPageSizeCap() const {
    return page_size_cap;
}

constexpr uint32_t ibv::device::Attributes::getVendorId() const {
    return vendor_id;
}

constexpr uint32_t ibv::device::Attributes::getVendorPartId() const {
    return vendor_part_id;
}

constexpr uint32_t ibv::device::Attributes::getHwVer() const {
    return hw_ver;
}

constexpr int ibv::device::Attributes::getMaxQp() const {
    return max_qp;
}

constexpr int ibv::device::Attributes::getMaxQpWr() const {
    return max_qp_wr;
}

constexpr bool ibv::device::Attributes::hasCapability(ibv::device::CapabilityFlag flag) const {
    const auto rawFlag = static_cast<ibv_device_cap_flags>(flag);
    return (device_cap_flags & rawFlag) == rawFlag;
}

constexpr int ibv::device::Attributes::getMaxSge() const {
    return max_sge;
}

constexpr int ibv::device::Attributes::getMaxSgeRd() const {
    return max_sge_rd;
}

constexpr int ibv::device::Attributes::getMaxCq() const {
    return max_cq;
}

constexpr int ibv::device::Attributes::getMaxCqe() const {
    return max_cqe;
}

constexpr int ibv::device::Attributes::getMaxMr() const {
    return max_mr;
}

constexpr int ibv::device::Attributes::getMaxPd() const {
    return max_pd;
}

constexpr int ibv::device::Attributes::getMaxQpRdAtom() const {
    return max_qp_rd_atom;
}

constexpr int ibv::device::Attributes::getMaxEeRdAtom() const {
    return max_ee_rd_atom;
}

constexpr int ibv::device::Attributes::getMaxResRdAtom() const {
    return max_res_rd_atom;
}

constexpr int ibv::device::Attributes::getMaxQpInitRdAtom() const {
    return max_qp_init_rd_atom;
}

constexpr int ibv::device::Attributes::getMaxEeInitRdAtom() const {
    return max_ee_init_rd_atom;
}

constexpr ibv::device::AtomicCapabilities ibv::device::Attributes::getAtomicCap() const {
    return static_cast<AtomicCapabilities>(atomic_cap);
}

constexpr int ibv::device::Attributes::getMaxEe() const {
    return max_ee;
}

constexpr int ibv::device::Attributes::getMaxRdd() const {
    return max_rdd;
}

constexpr int ibv::device::Attributes::getMaxMw() const {
    return max_mw;
}

constexpr int ibv::device::Attributes::getMaxRawIpv6Qp() const {
    return max_raw_ipv6_qp;
}

constexpr int ibv::device::Attributes::getMaxRawEthyQp() const {
    return max_raw_ethy_qp;
}

constexpr int ibv::device::Attributes::getMaxMcastGrp() const {
    return max_mcast_grp;
}

constexpr int ibv::device::Attributes::getMaxMcastQpAttach() const {
    return max_mcast_qp_attach;
}

constexpr int ibv::device::Attributes::getMaxTotalMcastQpAttach() const {
    return max_total_mcast_qp_attach;
}

constexpr int ibv::device::Attributes::getMaxAh() const {
    return max_ah;
}

constexpr int ibv::device::Attributes::getMaxFmr() const {
    return max_fmr;
}

constexpr int ibv::device::Attributes::getMaxMapPerFmr() const {
    return max_map_per_fmr;
}

constexpr int ibv::device::Attributes::getMaxSrq() const {
    return max_srq;
}

constexpr int ibv::device::Attributes::getMaxSrqWr() const {
    return max_srq_wr;
}

constexpr int ibv::device::Attributes::getMaxSrqSge() const {
    return max_srq_sge;
}

constexpr uint16_t ibv::device::Attributes::getMaxPkeys() const {
    return max_pkeys;
}

constexpr uint8_t ibv::device::Attributes::getLocalCaAckDelay() const {
    return local_ca_ack_delay;
}

constexpr uint8_t ibv::device::Attributes::getPhysPortCnt() const {
    return phys_port_cnt;
}

inline const char *ibv::device::Device::getName() {
    return ibv_get_device_name(this);
}

inline uint64_t ibv::device::Device::getGUID() {
    return ibv_get_device_guid(this);
}

inline std::unique_ptr<ibv::context::Context> ibv::device::Device::open() {
    using Ctx = context::Context;
    const auto context = ibv_open_device(this);
    internal::checkPtr("ibv_open_device", context);
    return std::unique_ptr<Ctx>(reinterpret_cast<Ctx *>(context));
}

inline ibv::device::DeviceList::DeviceList() : devices(reinterpret_cast<Device **>(ibv_get_device_list(&num_devices))) {
    internal::checkPtr("ibv_get_device_list", devices);
}

inline ibv::device::DeviceList::~DeviceList() {
    if (devices != nullptr) {
        ibv_free_device_list(reinterpret_cast<ibv_device **>(devices));
    }
}

inline ibv::device::DeviceList::DeviceList(ibv::device::DeviceList &&other) noexcept {
    devices = other.devices;
    other.devices = nullptr;
    num_devices = other.num_devices;
    other.num_devices = 0;
}

constexpr ibv::device::DeviceList &ibv::device::DeviceList::operator=(ibv::device::DeviceList &&other) noexcept {
    if (devices != nullptr) {
        ibv_free_device_list(reinterpret_cast<ibv_device **>(devices));
    }
    devices = other.devices;
    other.devices = nullptr;
    num_devices = other.num_devices;
    other.num_devices = 0;
    return *this;
}

constexpr ibv::device::Device **ibv::device::DeviceList::begin() {
    return devices;
}

constexpr ibv::device::Device **ibv::device::DeviceList::end() {
    return &devices[num_devices];
}

constexpr size_t ibv::device::DeviceList::size() const {
    return static_cast<size_t>(num_devices);
}

constexpr ibv::device::Device *&ibv::device::DeviceList::operator[](int idx) {
    return devices[idx];
}

std::string ibv::memoryregion::to_string(ibv::memoryregion::ReregErrorCode ec) {
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

std::string ibv::memoryregion::to_string(const ibv::memoryregion::MemoryRegion &mr) {
    std::ostringstream addr;
    addr << mr.getAddr();
    return std::string("ptr=") + addr.str() + " size=" + std::to_string(mr.getLength()) + " key={..}";
}

constexpr ibv::memoryregion::RemoteAddress ibv::memoryregion::RemoteAddress::offset(uint64_t offset) const noexcept {
    return RemoteAddress{address + offset, rkey};
}

inline void ibv::memoryregion::MemoryRegion::operator delete(void *ptr) noexcept {
    const auto status = ibv_dereg_mr(reinterpret_cast<ibv_mr *>(ptr));
    internal::checkStatusNoThrow("ibv_dereg_mr", status);
}

inline ibv::context::Context *ibv::memoryregion::MemoryRegion::getContext() const {
    return reinterpret_cast<context::Context *>(context);
}

inline ibv::protectiondomain::ProtectionDomain *ibv::memoryregion::MemoryRegion::getPd() const {
    return reinterpret_cast<protectiondomain::ProtectionDomain *>(pd);
}

constexpr void *ibv::memoryregion::MemoryRegion::getAddr() const {
    return addr;
}

constexpr size_t ibv::memoryregion::MemoryRegion::getLength() const {
    return length;
}

constexpr uint32_t ibv::memoryregion::MemoryRegion::getHandle() const {
    return handle;
}

constexpr uint32_t ibv::memoryregion::MemoryRegion::getLkey() const {
    return lkey;
}

constexpr uint32_t ibv::memoryregion::MemoryRegion::getRkey() const {
    return rkey;
}

inline ibv::memoryregion::Slice ibv::memoryregion::MemoryRegion::getSlice() {
    return Slice{reinterpret_cast<uintptr_t>(addr), static_cast<uint32_t>(length), lkey};
}

inline ibv::memoryregion::Slice ibv::memoryregion::MemoryRegion::getSlice(uint32_t offset, uint32_t sliceLength) {
    return Slice{reinterpret_cast<uintptr_t>(addr) + offset, sliceLength, lkey};
}

inline ibv::memoryregion::RemoteAddress ibv::memoryregion::MemoryRegion::getRemoteAddress() {
    return RemoteAddress{reinterpret_cast<uint64_t>(addr), rkey};
}

inline void ibv::memoryregion::MemoryRegion::reRegister(std::initializer_list<ibv::memoryregion::ReregFlag> changeFlags,
                                                        ibv::protectiondomain::ProtectionDomain *newPd, void *newAddr,
                                                        size_t newLength,
                                                        std::initializer_list<ibv::AccessFlag> accessFlags) {
    int changes = 0;
    for (auto change : changeFlags) {
        changes |= static_cast<ibv_rereg_mr_flags>(change);
    }
    int access = 0;
    for (auto accessFlag : accessFlags) {
        access |= static_cast<ibv_access_flags>(accessFlag);
    }
    const auto status = ibv_rereg_mr(this, changes, newPd, newAddr, newLength, access);

    if (status != 0) {
        const auto res = static_cast<ReregErrorCode>(status);
        throw std::runtime_error("ibv_rereg_mr failed with: " + to_string(res));
    }
}

constexpr ibv::workrequest::SendWr::SendWr() : ibv_send_wr{} {}

constexpr void ibv::workrequest::SendWr::setId(uint64_t id) {
    wr_id = id;
}

constexpr uint64_t ibv::workrequest::SendWr::getId() const {
    return wr_id;
}

constexpr void ibv::workrequest::SendWr::setNext(ibv::workrequest::SendWr *wrList) {
    next = wrList;
}

constexpr void ibv::workrequest::SendWr::setSge(ibv::memoryregion::Slice *scatterGatherArray, int size) {
    sg_list = scatterGatherArray;
    num_sge = size;
}

constexpr void ibv::workrequest::SendWr::setFlag(ibv::workrequest::Flags flag) {
    send_flags |= static_cast<ibv_send_flags>(flag);
}

constexpr void ibv::workrequest::SendWr::setFence() {
    setFlag(Flags::FENCE);
}

constexpr void ibv::workrequest::SendWr::setSignaled() {
    setFlag(Flags::SIGNALED);
}

constexpr void ibv::workrequest::SendWr::setSolicited() {
    setFlag(Flags::SOLICITED);
}

constexpr void ibv::workrequest::SendWr::setInline() {
    setFlag(Flags::INLINE);
}

constexpr void ibv::workrequest::SendWr::setIpCsum() {
    setFlag(Flags::IP_CSUM);
}

constexpr void ibv::workrequest::SendWr::setFlags(std::initializer_list<ibv::workrequest::Flags> flags) {
    send_flags = 0;
    for (const auto flag : flags) {
        setFlag(flag);
    }
}

constexpr void ibv::workrequest::SendWr::setOpcode(ibv::workrequest::Opcode opcode) {
    this->opcode = static_cast<ibv_wr_opcode>(opcode);
}

constexpr void ibv::workrequest::SendWr::setImmData(uint32_t data) {
    imm_data = data;
}

constexpr decltype(ibv::workrequest::SendWr::wr) &ibv::workrequest::SendWr::getWr() {
    return wr;
}

constexpr void ibv::workrequest::Rdma::setRemoteAddress(ibv::memoryregion::RemoteAddress remoteAddress) {
    getWr().rdma.remote_addr = remoteAddress.address;
    getWr().rdma.rkey = remoteAddress.rkey;
}

constexpr void ibv::workrequest::Rdma::setRemoteAddress(uint64_t remote_addr, uint32_t rkey) {
    getWr().rdma.remote_addr = remote_addr;
    getWr().rdma.rkey = rkey;
}

constexpr ibv::workrequest::Write::Write() {
    SendWr::setOpcode(Opcode::RDMA_WRITE);
}

constexpr ibv::workrequest::WriteWithImm::WriteWithImm() {
    WriteWithImm::setOpcode(Opcode::RDMA_WRITE_WITH_IMM);
}

constexpr ibv::workrequest::Send::Send() {
    SendWr::setOpcode(Opcode::SEND);
}

constexpr void ibv::workrequest::Send::setUDAddressHandle(ibv::ah::AddressHandle &ah) {
    getWr().ud.ah = &ah;
}

constexpr void ibv::workrequest::Send::setUDRemoteQueue(uint32_t qpn, uint32_t qkey) {
    getWr().ud.remote_qpn = qpn;
    getWr().ud.remote_qkey = qkey;
}

constexpr ibv::workrequest::SendWithImm::SendWithImm() {
    SendWr::setOpcode(Opcode::SEND_WITH_IMM);
}

constexpr ibv::workrequest::Read::Read() {
    SendWr::setOpcode(Opcode::RDMA_READ);
}

constexpr void ibv::workrequest::Atomic::setRemoteAddress(ibv::memoryregion::RemoteAddress remoteAddress) {
    getWr().atomic.remote_addr = remoteAddress.address;
    getWr().atomic.rkey = remoteAddress.rkey;
}

constexpr void ibv::workrequest::Atomic::setRemoteAddress(uint64_t remote_addr, uint32_t rkey) {
    getWr().atomic.remote_addr = remote_addr;
    getWr().atomic.rkey = rkey;
}

constexpr ibv::workrequest::AtomicCompareSwap::AtomicCompareSwap() {
    SendWr::setOpcode(Opcode::ATOMIC_CMP_AND_SWP);
}

constexpr ibv::workrequest::AtomicCompareSwap::AtomicCompareSwap(uint64_t compare, uint64_t swap)
    : AtomicCompareSwap() {
    setCompareValue(compare);
    setSwapValue(swap);
}

constexpr void ibv::workrequest::AtomicCompareSwap::setCompareValue(uint64_t value) {
    getWr().atomic.compare_add = value;
}

constexpr void ibv::workrequest::AtomicCompareSwap::setSwapValue(uint64_t value) {
    getWr().atomic.swap = value;
}

constexpr ibv::workrequest::AtomicFetchAdd::AtomicFetchAdd() {
    SendWr::setOpcode(Opcode::ATOMIC_FETCH_AND_ADD);
}

constexpr ibv::workrequest::AtomicFetchAdd::AtomicFetchAdd(uint64_t value) : AtomicFetchAdd() {
    setAddValue(value);
}

constexpr void ibv::workrequest::AtomicFetchAdd::setAddValue(uint64_t value) {
    getWr().atomic.compare_add = value;
}

constexpr void ibv::workrequest::Recv::setId(uint64_t id) {
    wr_id = id;
}

constexpr uint64_t ibv::workrequest::Recv::getId() const {
    return wr_id;
}

constexpr void ibv::workrequest::Recv::setNext(ibv::workrequest::Recv *next) {
    this->next = next;
}

constexpr void ibv::workrequest::Recv::setSge(ibv::memoryregion::Slice *scatterGatherArray, int size) {
    sg_list = scatterGatherArray;
    num_sge = size;
}

constexpr void ibv::memorywindow::BindInfo::setMr(ibv::memoryregion::MemoryRegion &memoryregion) {
    mr = &memoryregion;
}

constexpr void ibv::memorywindow::BindInfo::setAddr(uint64_t addr) {
    this->addr = addr;
}

constexpr void ibv::memorywindow::BindInfo::setLength(uint64_t length) {
    this->length = length;
}

constexpr void ibv::memorywindow::BindInfo::setMwAccessFlags(std::initializer_list<ibv::AccessFlag> accessFlags) {
    mw_access_flags = 0;
    for (auto accessFlag : accessFlags) {
        mw_access_flags |= static_cast<ibv_access_flags>(accessFlag);
    }
}

constexpr void ibv::memorywindow::Bind::setWrId(uint64_t id) {
    wr_id = id;
}

constexpr void ibv::memorywindow::Bind::setSendFlags(std::initializer_list<ibv::workrequest::Flags> flags) {
    send_flags = 0;
    for (auto flag : flags) {
        send_flags |= static_cast<ibv_send_flags>(flag);
    }
}

inline ibv::memorywindow::BindInfo &ibv::memorywindow::Bind::getBindInfo() {
    return reinterpret_cast<BindInfo &>(bind_info);
}

inline void ibv::memorywindow::MemoryWindow::operator delete(void *ptr) noexcept {
    const auto status = ibv_dealloc_mw(reinterpret_cast<ibv_mw *>(ptr));
    internal::checkStatusNoThrow("ibv_dealloc_mw", status);
}

inline ibv::context::Context *ibv::memorywindow::MemoryWindow::getContext() const {
    return reinterpret_cast<context::Context *>(context);
}

inline ibv::protectiondomain::ProtectionDomain *ibv::memorywindow::MemoryWindow::getPd() const {
    return reinterpret_cast<protectiondomain::ProtectionDomain *>(pd);
}

constexpr uint32_t ibv::memorywindow::MemoryWindow::getRkey() const {
    return rkey;
}

constexpr uint32_t ibv::memorywindow::MemoryWindow::getHandle() const {
    return handle;
}

constexpr ibv::memorywindow::Type ibv::memorywindow::MemoryWindow::getType() {
    return static_cast<Type>(type);
}

constexpr ibv::srq::Attributes::Attributes(uint32_t max_wr, uint32_t max_sge, uint32_t srq_limit) : ibv_srq_attr{max_wr, max_sge, srq_limit} {}

constexpr ibv::srq::InitAttributes::InitAttributes(ibv::srq::Attributes attrs, void *context) : ibv_srq_init_attr{context, attrs} {}

inline void ibv::srq::SharedReceiveQueue::operator delete(void *ptr) noexcept {
    const auto status = ibv_destroy_srq(reinterpret_cast<ibv_srq *>(ptr));
    internal::checkStatusNoThrow("ibv_destroy_srq", status);
}

inline void ibv::srq::SharedReceiveQueue::modify(ibv::srq::Attributes &attr,
                                                 std::initializer_list<ibv::srq::AttributeMask>
                                                     modifiedAttrs) {
    int modifiedMask = 0;
    for (auto mod : modifiedAttrs) {
        modifiedMask |= static_cast<ibv_srq_attr_mask>(mod);
    }

    const auto status = ibv_modify_srq(this, &attr, modifiedMask);
    internal::checkStatus("ibv_modify_srq", status);
}

inline void ibv::srq::SharedReceiveQueue::query(ibv::srq::Attributes &res) {
    const auto status = ibv_query_srq(this, &res);
    internal::checkStatus("ibv_query_srq", status);
}

inline ibv::srq::Attributes ibv::srq::SharedReceiveQueue::query() {
    Attributes res{};
    query(res);
    return res;
}

inline uint32_t ibv::srq::SharedReceiveQueue::getNumber() {
    uint32_t num = 0;
    const auto status = ibv_get_srq_num(this, &num);
    internal::checkStatus("ibv_get_srq_num", status);
    return num;
}

inline void ibv::srq::SharedReceiveQueue::postRecv(ibv::workrequest::Recv &wr, ibv::workrequest::Recv *&badWr) {
    const auto status = ibv_post_srq_recv(this, &wr, reinterpret_cast<ibv_recv_wr **>(&badWr));
    internal::checkStatus("ibv_post_srq_recv", status);
}

constexpr void
ibv::xrcd::InitAttributes::setValidComponents(std::initializer_list<ibv::xrcd::InitAttributesMask> masks) {
    uint32_t newMask = 0;
    for (auto mask : masks) {
        newMask |= static_cast<uint32_t>(mask);
    }
    this->comp_mask = newMask;
}

constexpr void ibv::xrcd::InitAttributes::setFd(int fd) {
    this->fd = fd;
}

constexpr void ibv::xrcd::InitAttributes::setOflags(std::initializer_list<ibv::xrcd::OpenFlags> oflags) {
    int flags = 0;
    for (auto flag : oflags) {
        flags |= static_cast<int>(flag);
    }
    this->oflags = flags;
}

inline void ibv::xrcd::ExtendedConnectionDomain::operator delete(void *ptr) noexcept {
    const auto status = ibv_close_xrcd(reinterpret_cast<ibv_xrcd *>(ptr));
    internal::checkStatusNoThrow("ibv_close_xrcd", status);
}

inline std::string ibv::queuepair::to_string(ibv::queuepair::State state) {
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

inline std::string ibv::queuepair::to_string(ibv::queuepair::MigrationState ms) {
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

constexpr uint32_t ibv::queuepair::Capabilities::getMaxSendWr() const {
    return max_send_wr;
}

constexpr uint32_t ibv::queuepair::Capabilities::getMaxRecvWr() const {
    return max_recv_wr;
}

constexpr uint32_t ibv::queuepair::Capabilities::getMaxSendSge() const {
    return max_send_sge;
}

constexpr uint32_t ibv::queuepair::Capabilities::getMaxRecvSge() const {
    return max_recv_sge;
}

constexpr uint32_t ibv::queuepair::Capabilities::getMaxInlineData() const {
    return max_inline_data;
}

constexpr void ibv::queuepair::OpenAttributes::setCompMask(std::initializer_list<ibv::queuepair::OpenAttrMask> masks) {
    uint32_t newMask = 0;
    for (auto mask : masks) {
        newMask |= static_cast<uint32_t>(mask);
    }
    this->comp_mask = newMask;
}

constexpr void ibv::queuepair::OpenAttributes::setQpNum(uint32_t qp_num) {
    this->qp_num = qp_num;
}

constexpr void ibv::queuepair::OpenAttributes::setXrcd(ibv::xrcd::ExtendedConnectionDomain &xrcd) {
    this->xrcd = &xrcd;
}

constexpr void ibv::queuepair::OpenAttributes::setQpContext(void *qp_context) {
    this->qp_context = qp_context;
}

constexpr void ibv::queuepair::OpenAttributes::setQpType(ibv::queuepair::Type qp_type) {
    this->qp_type = static_cast<ibv_qp_type>(qp_type);
}

constexpr ibv::queuepair::State ibv::queuepair::Attributes::getQpState() const {
    return static_cast<State>(qp_state);
}

constexpr void ibv::queuepair::Attributes::setQpState(ibv::queuepair::State qp_state) {
    this->qp_state = static_cast<ibv_qp_state>(qp_state);
}

constexpr void ibv::queuepair::Attributes::setCurQpState(ibv::queuepair::State cur_qp_state) {
    this->cur_qp_state = static_cast<ibv_qp_state>(cur_qp_state);
}

constexpr ibv::Mtu ibv::queuepair::Attributes::getPathMtu() const {
    return static_cast<Mtu>(path_mtu);
}

constexpr void ibv::queuepair::Attributes::setPathMtu(ibv::Mtu path_mtu) {
    this->path_mtu = static_cast<ibv_mtu>(path_mtu);
}

constexpr ibv::queuepair::MigrationState ibv::queuepair::Attributes::getPathMigState() const {
    return static_cast<MigrationState>(path_mig_state);
}

constexpr void ibv::queuepair::Attributes::setPathMigState(ibv::queuepair::MigrationState path_mig_state) {
    this->path_mig_state = static_cast<ibv_mig_state>(path_mig_state);
}

constexpr uint32_t ibv::queuepair::Attributes::getQkey() const {
    return qkey;
}

constexpr void ibv::queuepair::Attributes::setQkey(uint32_t qkey) {
    this->qkey = qkey;
}

constexpr uint32_t ibv::queuepair::Attributes::getRqPsn() const {
    return rq_psn;
}

constexpr void ibv::queuepair::Attributes::setRqPsn(uint32_t rq_psn) {
    this->rq_psn = rq_psn;
}

constexpr uint32_t ibv::queuepair::Attributes::getSqPsn() const {
    return sq_psn;
}

constexpr void ibv::queuepair::Attributes::setSqPsn(uint32_t sq_psn) {
    this->sq_psn = sq_psn;
}

constexpr uint32_t ibv::queuepair::Attributes::getDestQpNum() const {
    return dest_qp_num;
}

constexpr void ibv::queuepair::Attributes::setDestQpNum(uint32_t dest_qp_num) {
    this->dest_qp_num = dest_qp_num;
}

constexpr bool ibv::queuepair::Attributes::hasQpAccessFlags(ibv::AccessFlag flag) const {
    const auto rawFlag = static_cast<ibv_access_flags>(flag);
    return (qp_access_flags & rawFlag) == rawFlag;
}

constexpr void ibv::queuepair::Attributes::setQpAccessFlags(std::initializer_list<ibv::AccessFlag> qp_access_flags) {
    int raw = 0;
    for (auto flag : qp_access_flags) {
        raw |= static_cast<ibv_access_flags>(flag);
    }
    this->qp_access_flags = raw;
}

constexpr const ibv::queuepair::Capabilities &ibv::queuepair::Attributes::getCap() const {
    return *static_cast<const Capabilities *>(&cap);
}

constexpr void ibv::queuepair::Attributes::setCap(const ibv::queuepair::Capabilities &cap) {
    this->cap = cap;
}

constexpr const ibv::ah::Attributes &ibv::queuepair::Attributes::getAhAttr() const {
    return *static_cast<const ah::Attributes *>(&ah_attr);
}

constexpr void ibv::queuepair::Attributes::setAhAttr(const ibv::ah::Attributes &ah_attr) {
    this->ah_attr = ah_attr;
}

constexpr const ibv::ah::Attributes &ibv::queuepair::Attributes::getAltAhAttr() const {
    return *static_cast<const ah::Attributes *>(&alt_ah_attr);
}

constexpr void ibv::queuepair::Attributes::setAltAhAttr(const ibv::ah::Attributes &alt_ah_attr) {
    this->alt_ah_attr = alt_ah_attr;
}

constexpr uint16_t ibv::queuepair::Attributes::getPkeyIndex() const {
    return pkey_index;
}

constexpr void ibv::queuepair::Attributes::setPkeyIndex(uint16_t pkey_index) {
    this->pkey_index = pkey_index;
}

constexpr uint16_t ibv::queuepair::Attributes::getAltPkeyIndex() const {
    return alt_pkey_index;
}

constexpr void ibv::queuepair::Attributes::setAltPkeyIndex(uint16_t alt_pkey_index) {
    this->alt_pkey_index = alt_pkey_index;
}

constexpr uint8_t ibv::queuepair::Attributes::getEnSqdAsyncNotify() const {
    return en_sqd_async_notify;
}

constexpr void ibv::queuepair::Attributes::setEnSqdAsyncNotify(uint8_t en_sqd_async_notify) {
    this->en_sqd_async_notify = en_sqd_async_notify;
}

constexpr uint8_t ibv::queuepair::Attributes::getSqDraining() const {
    return sq_draining;
}

constexpr uint8_t ibv::queuepair::Attributes::getMaxRdAtomic() const {
    return max_rd_atomic;
}

constexpr void ibv::queuepair::Attributes::setMaxRdAtomic(uint8_t max_rd_atomic) {
    this->max_rd_atomic = max_rd_atomic;
}

constexpr uint8_t ibv::queuepair::Attributes::getMaxDestRdAtomic() const {
    return max_dest_rd_atomic;
}

constexpr void ibv::queuepair::Attributes::setMaxDestRdAtomic(uint8_t max_dest_rd_atomic) {
    this->max_dest_rd_atomic = max_dest_rd_atomic;
}

constexpr uint8_t ibv::queuepair::Attributes::getMinRnrTimer() const {
    return min_rnr_timer;
}

constexpr void ibv::queuepair::Attributes::setMinRnrTimer(uint8_t min_rnr_timer) {
    this->min_rnr_timer = min_rnr_timer;
}

constexpr uint8_t ibv::queuepair::Attributes::getPortNum() const {
    return port_num;
}

constexpr void ibv::queuepair::Attributes::setPortNum(uint8_t port_num) {
    this->port_num = port_num;
}

constexpr uint8_t ibv::queuepair::Attributes::getTimeout() const {
    return timeout;
}

constexpr void ibv::queuepair::Attributes::setTimeout(uint8_t timeout) {
    this->timeout = timeout;
}

constexpr uint8_t ibv::queuepair::Attributes::getRetryCnt() const {
    return retry_cnt;
}

constexpr void ibv::queuepair::Attributes::setRetryCnt(uint8_t retry_cnt) {
    this->retry_cnt = retry_cnt;
}

constexpr uint8_t ibv::queuepair::Attributes::getRnrRetry() const {
    return rnr_retry;
}

constexpr void ibv::queuepair::Attributes::setRnrRetry(uint8_t rnr_retry) {
    this->rnr_retry = rnr_retry;
}

constexpr uint8_t ibv::queuepair::Attributes::getAltPortNum() const {
    return alt_port_num;
}

constexpr void ibv::queuepair::Attributes::setAltPortNum(uint8_t alt_port_num) {
    this->alt_port_num = alt_port_num;
}

constexpr uint8_t ibv::queuepair::Attributes::getAltTimeout() const {
    return alt_timeout;
}

constexpr void ibv::queuepair::Attributes::setAltTimeout(uint8_t alt_timeout) {
    this->alt_timeout = alt_timeout;
}

constexpr void ibv::queuepair::InitAttributes::setContext(void *context) {
    qp_context = context;
}

constexpr void ibv::queuepair::InitAttributes::setSendCompletionQueue(ibv::completions::CompletionQueue &cq) {
    send_cq = &cq;
}

constexpr void ibv::queuepair::InitAttributes::setRecvCompletionQueue(ibv::completions::CompletionQueue &cq) {
    recv_cq = &cq;
}

constexpr void ibv::queuepair::InitAttributes::setSharedReceiveQueue(ibv::srq::SharedReceiveQueue &sharedReceiveQueue) {
    srq = &sharedReceiveQueue;
}

constexpr void ibv::queuepair::InitAttributes::setCapabilities(const ibv::queuepair::Capabilities &caps) {
    cap = caps;
}

constexpr void ibv::queuepair::InitAttributes::setType(ibv::queuepair::Type type) {
    qp_type = static_cast<ibv_qp_type>(type);
}

constexpr void ibv::queuepair::InitAttributes::setSignalAll(bool shouldSignal) {
    sq_sig_all = static_cast<int>(shouldSignal);
}

inline void ibv::queuepair::QueuePair::operator delete(void *ptr) noexcept {
    const auto status = ibv_destroy_qp(reinterpret_cast<ibv_qp *>(ptr));
    internal::checkStatusNoThrow("ibv_destroy_qp", status);
}

constexpr uint32_t ibv::queuepair::QueuePair::getNum() const {
    return qp_num;
}

inline void ibv::queuepair::QueuePair::modify(ibv::queuepair::Attributes &attr,
                                              std::initializer_list<ibv::queuepair::AttrMask>
                                                  modifiedAttributes) {
    int mask = 0;
    for (auto mod : modifiedAttributes) {
        mask |= static_cast<ibv_qp_attr_mask>(mod);
    }
    const auto status = ibv_modify_qp(this, &attr, mask);
    internal::checkStatus("ibv_modify_qp", status);
}

inline void ibv::queuepair::QueuePair::query(ibv::queuepair::Attributes &attr,
                                             std::initializer_list<ibv::queuepair::AttrMask>
                                                 queriedAttributes,
                                             ibv::queuepair::InitAttributes &init_attr,
                                             std::initializer_list<ibv::queuepair::InitAttrMask>
                                                 queriedInitAttributes) {
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

inline std::tuple<ibv::queuepair::Attributes, ibv::queuepair::InitAttributes>
ibv::queuepair::QueuePair::query(std::initializer_list<ibv::queuepair::AttrMask> queriedAttributes,
                                 std::initializer_list<ibv::queuepair::InitAttrMask>
                                     queriedInitAttributes) {
    Attributes attributes;
    InitAttributes initAttributes;
    query(attributes, queriedAttributes, initAttributes, queriedInitAttributes);
    return {attributes, initAttributes};
}

inline ibv::queuepair::Attributes
ibv::queuepair::QueuePair::query(std::initializer_list<ibv::queuepair::AttrMask> queriedAttributes) {
    return std::get<0>(query(queriedAttributes, {}));
}

inline ibv::queuepair::InitAttributes
ibv::queuepair::QueuePair::query(std::initializer_list<ibv::queuepair::InitAttrMask> queriedInitAttributes) {
    return std::get<1>(query({}, queriedInitAttributes));
}

inline void ibv::queuepair::QueuePair::postSend(ibv::workrequest::SendWr &wr, ibv::workrequest::SendWr *&bad_wr) {
    const auto status = ibv_post_send(this, &wr, reinterpret_cast<ibv_send_wr **>(&bad_wr));
    internal::checkStatus("ibv_post_send", status);
}

inline void ibv::queuepair::QueuePair::postRecv(ibv::workrequest::Recv &wr, ibv::workrequest::Recv *&bad_wr) {
    const auto status = ibv_post_recv(this, &wr, reinterpret_cast<ibv_recv_wr **>(&bad_wr));
    internal::checkStatus("ibv_post_recv", status);
}

inline std::unique_ptr<ibv::flow::Flow> ibv::queuepair::QueuePair::createFlow(ibv::flow::Attributes &attr) {
    auto res = ibv_create_flow(this, &attr);
    internal::checkPtr("ibv_create_flow", res);
    return std::unique_ptr<flow::Flow>(reinterpret_cast<flow::Flow *>(res));
}

inline uint32_t
ibv::queuepair::QueuePair::bindMemoryWindow(ibv::memorywindow::MemoryWindow &mw, ibv::memorywindow::Bind &info) {
    const auto status = ibv_bind_mw(this, &mw, &info);
    internal::checkStatus("ibv_bind_mw", status);
    return mw.getRkey();
}

inline void ibv::queuepair::QueuePair::attachToMcastGroup(const ibv::Gid &gid, uint16_t lid) {
    const auto status = ibv_attach_mcast(this, &gid.underlying, lid);
    internal::checkStatus("ibv_attach_mcast", status);
}

inline void ibv::queuepair::QueuePair::detachFromMcastGroup(const ibv::Gid &gid, uint16_t lid) {
    const auto status = ibv_detach_mcast(this, &gid.underlying, lid);
    internal::checkStatus("ibv_detach_mcast", status);
}

constexpr ibv::event::Type ibv::event::AsyncEvent::getType() const {
    return static_cast<Type>(event_type);
}

constexpr ibv::event::Cause ibv::event::AsyncEvent::getCause() const {
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
    __builtin_unreachable();
}

inline ibv::queuepair::QueuePair *ibv::event::AsyncEvent::getCausingQp() const {
    checkCause(Cause::QueuePair);
    return reinterpret_cast<queuepair::QueuePair *>(element.qp);
}

inline ibv::completions::CompletionQueue *ibv::event::AsyncEvent::getCausingCq() const {
    checkCause(Cause::CompletionQueue);
    return reinterpret_cast<completions::CompletionQueue *>(element.cq);
}

inline ibv::srq::SharedReceiveQueue *ibv::event::AsyncEvent::getCausingSrq() const {
    checkCause(Cause::SharedReceiveQueue);
    return reinterpret_cast<srq::SharedReceiveQueue *>(element.srq);
}

constexpr int ibv::event::AsyncEvent::getCausingPort() const {
    checkCause(Cause::Port);
    return element.port_num;
}

inline void ibv::event::AsyncEvent::ack() {
    ibv_ack_async_event(this);
}

constexpr void ibv::event::AsyncEvent::checkCause(ibv::event::Cause cause) const {
    if (getCause() != cause) {
        throw std::logic_error("Invalid event cause accessed");
    }
}

inline void ibv::protectiondomain::ProtectionDomain::operator delete(void *ptr) noexcept {
    const auto status = ibv_dealloc_pd(reinterpret_cast<ibv_pd *>(ptr));
    internal::checkStatusNoThrow("ibv_dealloc_pd", status);
}

inline ibv::context::Context *ibv::protectiondomain::ProtectionDomain::getContext() const {
    return reinterpret_cast<context::Context *>(context);
}

constexpr uint32_t ibv::protectiondomain::ProtectionDomain::getHandle() const {
    return handle;
}

inline std::unique_ptr<ibv::memoryregion::MemoryRegion>
ibv::protectiondomain::ProtectionDomain::registerMemoryRegion(void *addr, size_t length,
                                                              std::initializer_list<ibv::AccessFlag> flags) {
    using MR = memoryregion::MemoryRegion;
    int access = 0;
    for (auto flag : flags) {
        access |= static_cast<ibv_access_flags>(flag);
    }
    const auto mr = ibv_reg_mr(this, addr, length, access);
    internal::checkPtr("ibv_reg_mr", mr);
    return std::unique_ptr<MR>(reinterpret_cast<MR *>(mr));
}

inline std::unique_ptr<ibv::memorywindow::MemoryWindow>
ibv::protectiondomain::ProtectionDomain::allocMemoryWindow(ibv::memorywindow::Type type) {
    using MW = memorywindow::MemoryWindow;
    const auto mw = ibv_alloc_mw(this, static_cast<ibv_mw_type>(type));
    internal::checkPtr("ibv_alloc_mw", mw);
    return std::unique_ptr<MW>(reinterpret_cast<MW *>(mw));
}

inline std::unique_ptr<ibv::srq::SharedReceiveQueue>
ibv::protectiondomain::ProtectionDomain::createSrq(ibv::srq::InitAttributes &initAttributes) {
    using SRQ = srq::SharedReceiveQueue;
    const auto srq = ibv_create_srq(this, &initAttributes);
    internal::checkPtr("ibv_create_srq", srq);
    return std::unique_ptr<SRQ>(reinterpret_cast<SRQ *>(srq));
}

inline std::unique_ptr<ibv::queuepair::QueuePair>
ibv::protectiondomain::ProtectionDomain::createQueuePair(ibv::queuepair::InitAttributes &initAttributes) {
    using QP = queuepair::QueuePair;
    const auto qp = ibv_create_qp(this, &initAttributes);
    internal::checkPtr("ibv_create_qp", qp);
    return std::unique_ptr<QP>(reinterpret_cast<QP *>(qp));
}

inline std::unique_ptr<ibv::ah::AddressHandle>
ibv::protectiondomain::ProtectionDomain::createAddressHandle(ibv::ah::Attributes attributes) {
    using AH = ah::AddressHandle;
    const auto ah = ibv_create_ah(this, &attributes);
    internal::checkPtr("ibv_create_ah", ah);
    return std::unique_ptr<AH>(reinterpret_cast<AH *>(ah));
}

inline std::unique_ptr<ibv::ah::AddressHandle>
ibv::protectiondomain::ProtectionDomain::createAddressHandleFromWorkCompletion(ibv::workcompletion::WorkCompletion &wc,
                                                                               ibv::GlobalRoutingHeader *grh,
                                                                               uint8_t port_num) {
    using AH = ah::AddressHandle;
    const auto ah = ibv_create_ah_from_wc(this, &wc, grh, port_num);
    internal::checkPtr("ibv_create_ah_from_wc", ah);
    return std::unique_ptr<AH>(reinterpret_cast<AH *>(ah));
}

inline void ibv::context::Context::operator delete(void *ptr) noexcept {
    const auto status = ibv_close_device(reinterpret_cast<ibv_context *>(ptr));
    internal::checkStatusNoThrow("ibv_close_device", status);
}

inline ibv::device::Device *ibv::context::Context::getDevice() const {
    return reinterpret_cast<device::Device *>(device);
}

inline ibv::device::Attributes ibv::context::Context::queryAttributes() {
    device::Attributes res;
    const auto status = ibv_query_device(this, &res);
    internal::checkStatus("ibv_query_device", status);
    return res;
}

inline ibv::port::Attributes ibv::context::Context::queryPort(uint8_t port) {
    port::Attributes res;
    const auto status = ibv_query_port(this, port, &res);
    internal::checkStatus("ibv_query_port", status);
    return res;
}

inline ibv::event::AsyncEvent ibv::context::Context::getAsyncEvent() {
    event::AsyncEvent res{};
    const auto status = ibv_get_async_event(this, &res);
    internal::checkStatus("ibv_get_async_event", status);
    return res;
}

inline ibv::Gid ibv::context::Context::queryGid(uint8_t port_num, int index) {
    Gid res{};
    const auto status = ibv_query_gid(this, port_num, index, &res.underlying);
    internal::checkStatus("ibv_query_gid", status);
    return res;
}

inline uint16_t ibv::context::Context::queryPkey(uint8_t port_num, int index) {
    uint16_t res{};
    const auto status = ibv_query_pkey(this, port_num, index, &res);
    internal::checkStatus("ibv_query_pkey", status);
    return res;
}

inline std::unique_ptr<ibv::protectiondomain::ProtectionDomain> ibv::context::Context::allocProtectionDomain() {
    using PD = protectiondomain::ProtectionDomain;
    const auto pd = ibv_alloc_pd(this);
    internal::checkPtr("ibv_alloc_pd", pd);
    return std::unique_ptr<PD>(reinterpret_cast<PD *>(pd));
}

inline std::unique_ptr<ibv::xrcd::ExtendedConnectionDomain>
ibv::context::Context::openExtendedConnectionDomain(ibv::xrcd::InitAttributes &attr) {
    using XRCD = xrcd::ExtendedConnectionDomain;
    const auto xrcd = ibv_open_xrcd(this, &attr);
    internal::checkPtr("ibv_open_xrcd", xrcd);
    return std::unique_ptr<XRCD>(reinterpret_cast<XRCD *>(xrcd));
}

inline std::unique_ptr<ibv::completions::CompletionEventChannel> ibv::context::Context::createCompletionEventChannel() {
    using CEC = completions::CompletionEventChannel;
    const auto compChannel = ibv_create_comp_channel(this);
    internal::checkPtr("ibv_create_comp_channel", compChannel);
    return std::unique_ptr<CEC>(reinterpret_cast<CEC *>(compChannel));
}

inline std::unique_ptr<ibv::completions::CompletionQueue>
ibv::context::Context::createCompletionQueue(int cqe, void *context, ibv::completions::CompletionEventChannel &cec,
                                             int completionVector) {
    using CQ = completions::CompletionQueue;
    const auto cq = ibv_create_cq(this, cqe, context, &cec, completionVector);
    internal::checkPtr("ibv_create_cq", cq);
    return std::unique_ptr<CQ>(reinterpret_cast<CQ *>(cq));
}

inline std::unique_ptr<ibv::queuepair::QueuePair>
ibv::context::Context::openSharableQueuePair(ibv::queuepair::OpenAttributes &openAttributes) {
    using QP = queuepair::QueuePair;
    const auto qp = ibv_open_qp(this, &openAttributes);
    internal::checkPtr("ibv_open_qp", qp);
    return std::unique_ptr<QP>(reinterpret_cast<QP *>(qp));
}

inline void
ibv::context::Context::initAhAttributesFromWorkCompletion(uint8_t port_num, ibv::workcompletion::WorkCompletion &wc,
                                                          ibv::GlobalRoutingHeader *grh,
                                                          ibv::ah::Attributes &attributes) {
    const auto status = ibv_init_ah_from_wc(this, port_num, &wc, grh, &attributes);
    internal::checkStatus("ibv_init_ah_from_wc", status);
}

inline ibv::ah::Attributes
ibv::context::Context::getAhAttributesFromWorkCompletion(uint8_t port_num, ibv::workcompletion::WorkCompletion &wc,
                                                         ibv::GlobalRoutingHeader *grh) {
    ah::Attributes attributes;
    initAhAttributesFromWorkCompletion(port_num, wc, grh, attributes);
    return attributes;
}

#endif
