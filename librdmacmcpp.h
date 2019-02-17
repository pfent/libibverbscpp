#ifndef LIBRDMACMCPP_LIBRARY_H
#define LIBRDMACMCPP_LIBRARY_H

#include "libibverbscpp.h"
#include <rdma/rdma_cma.h>

namespace rdma {
    namespace internal {
        using ibv::internal::exception;
        using ibv::internal::PointerOnly;
        using ibv::internal::checkStatus;
        using ibv::internal::checkStatusNoThrow;
        using ibv::internal::checkPtr;
    }

    enum class PortSpace : std::underlying_type_t<rdma_port_space> {
        TCP = RDMA_PS_TCP,
        UDP = RDMA_PS_UDP,
        IB = RDMA_PS_IB,
    };

    class ID : public rdma_cm_id, public internal::PointerOnly {
        using rdma_cm_id::verbs;
        using rdma_cm_id::channel;
        using rdma_cm_id::context;
        using rdma_cm_id::qp;
        using rdma_cm_id::route;
        using rdma_cm_id::ps;
        using rdma_cm_id::port_num;
        using rdma_cm_id::event;
        using rdma_cm_id::send_cq_channel;
        using rdma_cm_id::send_cq;
        using rdma_cm_id::recv_cq_channel;
        using rdma_cm_id::recv_cq;
        using rdma_cm_id::srq;
        using rdma_cm_id::pd;
        using rdma_cm_id::qp_type;
    public:
        static void *operator new(std::size_t) noexcept = delete;

        static void operator delete(void *ptr) noexcept;

        constexpr void setContext(void *context);
    };

    static_assert(sizeof(ID) == sizeof(rdma_cm_id), "");

    namespace event {
        enum class Type : std::underlying_type_t<rdma_cm_event_type> {
            ADDR_RESOLVED = RDMA_CM_EVENT_ADDR_RESOLVED,
            ADDR_ERROR = RDMA_CM_EVENT_ADDR_ERROR,
            ROUTE_RESOLVED = RDMA_CM_EVENT_ROUTE_RESOLVED,
            ROUTE_ERROR = RDMA_CM_EVENT_ROUTE_ERROR,
            CONNECT_REQUEST = RDMA_CM_EVENT_CONNECT_REQUEST,
            CONNECT_RESPONSE = RDMA_CM_EVENT_CONNECT_RESPONSE,
            CONNECT_ERROR = RDMA_CM_EVENT_CONNECT_ERROR,
            UNREACHABLE = RDMA_CM_EVENT_UNREACHABLE,
            REJECTED = RDMA_CM_EVENT_REJECTED,
            ESTABLISHED = RDMA_CM_EVENT_ESTABLISHED,
            DISCONNECTED = RDMA_CM_EVENT_DISCONNECTED,
            DEVICE_REMOVAL = RDMA_CM_EVENT_DEVICE_REMOVAL,
            MULTICAST_JOIN = RDMA_CM_EVENT_MULTICAST_JOIN,
            MULTICAST_ERROR = RDMA_CM_EVENT_MULTICAST_ERROR,
            ADDR_CHANGE = RDMA_CM_EVENT_ADDR_CHANGE,
            TIMEWAIT_EXIT = RDMA_CM_EVENT_TIMEWAIT_EXIT
        };

        [[nodiscard]]
        const char *eventStr(Type t);

        class Event : public rdma_cm_event, public internal::PointerOnly {
            using rdma_cm_event::id;
            using rdma_cm_event::listen_id;
            using rdma_cm_event::event;
            using rdma_cm_event::status;
            using rdma_cm_event::param;
        public:
            static void *operator new(std::size_t) noexcept = delete;

            static void operator delete(void *ptr) noexcept;

            [[nodiscard]]
            ID* getID() const;

            [[nodiscard]]
            ID* getListenID() const;

            [[nodiscard]]
            Type getType() const;

            [[nodiscard]]
            int getStatus() const;

            [[nodiscard]]
            const rdma_conn_param& getConnParam() const;

            [[nodiscard]]
            const rdma_ud_param& getUDParam() const;
        };

        static_assert(sizeof(Event) == sizeof(rdma_cm_event), "");

        class Channel : public rdma_event_channel, public internal::PointerOnly {
            using rdma_event_channel::fd;
        public:
            static void *operator new(std::size_t) noexcept = delete;

            static void operator delete(void *ptr) noexcept;

            [[nodiscard]]
            std::unique_ptr<ID> createID(void *context, PortSpace ps);

            [[nodiscard]]
            std::unique_ptr<Event> getEvent();
        };

        static_assert(sizeof(Channel) == sizeof(rdma_event_channel), "");
    }

    std::unique_ptr<event::Channel> createEventChannel();

/**********************************************************************************************************************/
} // namespace rdma

inline std::unique_ptr<rdma::event::Channel> rdma::createEventChannel() {
    using EC = rdma::event::Channel;
    const auto eventChannel = rdma_create_event_channel();
    if (eventChannel == nullptr && errno == ENODEV)
        throw internal::exception("rdma_create_event_channel - No RDMA devices were detected", errno);
    internal::checkPtr("rdma_create_event_channel", eventChannel);
    return std::unique_ptr<EC>(reinterpret_cast<EC *>(eventChannel));
}

inline std::unique_ptr<rdma::ID>
rdma::event::Channel::createID(void *context, PortSpace ps)
{
    rdma_cm_id *id;
    int ret = rdma_create_id(this, &id, context, static_cast<rdma_port_space>(ps));
    internal::checkStatus("rdma_create_id", ret);
    return std::unique_ptr<ID>(reinterpret_cast<ID *>(id));
}

inline std::unique_ptr<rdma::event::Event> rdma::event::Channel::getEvent()
{
    rdma_cm_event *event;
    int ret = rdma_get_cm_event(this, &event);
    internal::checkStatus("rdma_get_cm_event", ret);
    return std::unique_ptr<Event>(reinterpret_cast<Event *>(event));
}

inline void rdma::event::Channel::operator delete(void *ptr) noexcept {
    rdma_destroy_event_channel(reinterpret_cast<rdma_event_channel *>(ptr));
}

constexpr void rdma::ID::setContext(void *context) {
    this->context = context;
}

inline void rdma::ID::operator delete(void *ptr) noexcept {
    rdma_destroy_id(reinterpret_cast<rdma_cm_id *>(ptr));
}

inline void rdma::event::Event::operator delete(void *ptr) noexcept {
    int ret = rdma_ack_cm_event(reinterpret_cast<rdma_cm_event *>(ptr));
    internal::checkStatusNoThrow("cannot acknowledge event", ret);
}

inline const char *rdma::event::eventStr(Type t)
{
    return rdma_event_str(static_cast<rdma_cm_event_type>(t));
}

inline rdma::ID* rdma::event::Event::getID() const
{
    return reinterpret_cast<ID *>(id);
}

inline rdma::ID* rdma::event::Event::getListenID() const
{
    return reinterpret_cast<ID *>(listen_id);
}

inline rdma::event::Type rdma::event::Event::getType() const
{
    return static_cast<Type>(event);
}

inline int rdma::event::Event::getStatus() const
{
    return status;
}

inline const rdma_conn_param& rdma::event::Event::getConnParam() const
{
    return param.conn;
}

inline const rdma_ud_param& rdma::event::Event::getUDParam() const
{
    return param.ud;
}

#endif
