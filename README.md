# libibverbscpp - Modern C++ bindings for libibverbs

> `libibverbs` is a library that allows userspace processes to use InfiniBand/RDMA "verbs" directly.

However, libibverbs only has C bindings, with little type-safety and a bug-prone manual deallocation mechanism.
 
As `libibverbs` already uses some object-oriented approaches, the C++ wrapper can provide stronger types and RAII mechanisms
for resource management.

### Building
You'll probably need a reasonably modern compiler for this with basic C++14 support. 

libibverbscpp is currently header-only. Adding it to the include path and linking libibverbs should be sufficient.

```cmake
project(foo)
include_directories(libibverbscpp)
target_link_libraries(foo libibverbs)
```

### Examples
```C++
std::byte msg[8];
auto list = ibv::device::DeviceList();
auto ctx = list[0]->open();
auto pd = ctx->allocProtectionDomain();
auto mr = pd->registerMemoryRegion(&msg, 8, {/* no remote access */});
auto qpAttr = ibv::queuepair::InitAttributes();
// TODO: properly set up and connect QueuePair
auto qp = pd->createQueuePair(qpAttr);
auto wr = ibv::workrequest::Simple<ibv::workrequest::Write>();
// TODO: properly set up remote address
wr.setRemoteAddress(ibv::memoryregion::RemoteAddress());
wr.setLocalAddress(mr->getSlice());
ibv::workrequest::SendWr *bad;
qp->postSend(wr, bad);
// no explicit teardown needed
```

### Resource management
All allocations return a `std::unique_ptr<T>`, which automatically handles exception-safe teardown. In error cases, an
exception is thrown, similarly to how `opertor new()` handles failing cases.
Since libibverbs deallocation can potentially fail (e.g. wrong deallocation order), this is treated as fatal and the 
error printed to `stderr`. However future releases might call `std::terminate` right away.

### License
This project is licensed under the same terms as [libibverbs](https://github.com/linux-rdma/rdma-core), i.e. dually 
licensed under BSD/MIT and GPLv2
