#ifndef LIBRDMACMCPP_LIBRARY_H
#define LIBRDMACMCPP_LIBRARY_H

#include "libibverbscpp.h"
#include <rdma/rdma_cma.h>

namespace rdma {
    namespace internal {
        using ibv::internal::exception;
        using ibv::internal::PointerOnly;
        using ibv::internal::checkPtr;
    }

    class EventChannel : public rdma_event_channel, public internal::PointerOnly {
        using rdma_event_channel::fd;
    public:
        static void *operator new(std::size_t) noexcept = delete;

        static void operator delete(void *ptr) noexcept;
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

inline void rdma::EventChannel::operator delete(void *ptr) noexcept {
    rdma_destroy_event_channel(reinterpret_cast<rdma_event_channel *>(ptr));
}


#endif
