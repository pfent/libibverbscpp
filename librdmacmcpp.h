#ifndef LIBRDMACMCPP_LIBRARY_H
#define LIBRDMACMCPP_LIBRARY_H

#include "libibverbscpp.h"
#include <rdma/rdma_cma.h>

namespace rdma {
    namespace internal {
        using ibv::internal::exception;
        using ibv::internal::PointerOnly;
        using ibv::internal::checkStatus;
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

    class EventChannel : public rdma_event_channel, public internal::PointerOnly {
        using rdma_event_channel::fd;
    public:
        static void *operator new(std::size_t) noexcept = delete;

        static void operator delete(void *ptr) noexcept;

	[[nodiscard]]
	std::unique_ptr<ID> createID(void *context, PortSpace ps);
    };

    static_assert(sizeof(EventChannel) == sizeof(rdma_event_channel), "");

    std::unique_ptr<EventChannel> createEventChannel();

/**********************************************************************************************************************/
} // namespace rdma

inline std::unique_ptr<rdma::EventChannel> rdma::createEventChannel() {
    using EC = rdma::EventChannel;
    const auto eventChannel = rdma_create_event_channel();
    if (eventChannel == nullptr && errno == ENODEV)
        throw internal::exception("rdma_create_event_channel - No RDMA devices were detected", errno);
    internal::checkPtr("rdma_create_event_channel", eventChannel);
    return std::unique_ptr<EC>(reinterpret_cast<EC *>(eventChannel));
}

inline std::unique_ptr<rdma::ID>
rdma::EventChannel::createID(void *context, PortSpace ps)
{
    rdma_cm_id *id;
    int ret = rdma_create_id(this, &id, context, static_cast<rdma_port_space>(ps));
    internal::checkStatus("rdma_create_id", ret);
    return std::unique_ptr<ID>(reinterpret_cast<ID *>(id));
}

inline void rdma::EventChannel::operator delete(void *ptr) noexcept {
    rdma_destroy_event_channel(reinterpret_cast<rdma_event_channel *>(ptr));
}

constexpr void rdma::ID::setContext(void *context) {
    this->context = context;
}

inline void rdma::ID::operator delete(void *ptr) noexcept {
    rdma_destroy_id(reinterpret_cast<rdma_cm_id *>(ptr));
}

#endif
