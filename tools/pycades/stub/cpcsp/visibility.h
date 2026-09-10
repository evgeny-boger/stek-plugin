/* Stub for CSP >= 5.0.12900 header missing from the 5.0.12000 devel package.
   Only CPRO_PUBLIC_API is referenced by the cades 2.0.15700 headers. */
#ifndef CPRO_PUBLIC_API
#define CPRO_PUBLIC_API __attribute__((visibility("default")))
#endif
/* cades 2.0.15700 headers reference NS_SHARED_PTR::shared_ptr; libcppcades
   exports std::shared_ptr signatures (nm -DC), so bind it to std. */
#include <memory>
#ifndef NS_SHARED_PTR
#define NS_SHARED_PTR std
#endif
