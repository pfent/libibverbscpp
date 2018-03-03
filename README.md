# libibverbscpp - Modern C++ bindings for libibverbs

> libibverbs is a library that allows userspace processes to use InfiniBand/RDMA "verbs" directly.

However, libibverbs only has C bindings, with little type-safety and a bug-prone manual deallocation mechanisms.
 
As libibverbs already uses some object-oriented approaches, so a C++ wrapper providing strong types and RAII mechanisms
for resource management.  

### Building
You'll probably need a reasonably modern compiler for this with basic C++17 support. 

libibverbscpp is currently header-only. Adding it to the include path and linking libibverbs should be sufficient.

```cmake
project(foo)
include_directories(libibverbscpp)
target_link_libraries(foo libibverbs)
```

### Examples
TODO workrequest example:
* DeviceList()
* device.open()
* context->allocProtectionDomain()
* protectiondomain.createQueuePair()
* create workrequest
* queuepair.postWorkRequest()

### License
This project is licensed under the same terms as [libibverbs](https://github.com/linux-rdma/rdma-core), i.e. dually 
licensed under BSD/MIT and GPLv2
