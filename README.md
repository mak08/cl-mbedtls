# cl-mbedtls
CFFI bindings for mbedTLS

## Description
cl-mbedtls provides CFFI bindings for [mbedTLS](https://www.mbed.com/en/technologies/security/mbed-tls/), a secure networking and encryption library. cl-mbedtls is still work in progress. It currently provides enough features to run [PolarSeal](https://github.com/mak08/polarseal). 

## Installation
* Configure & build mbedTLS 
  * Download and unpack [mbedTLS](https://www.mbed.com/en/technologies/security/mbed-tls/#Get_mbed_TLS)
  * Enable MBEDTLS_THREADING_PTHREAD and MBEDTLS_THREADING_C in include/mbedtls/config.h
  * Build mbedTLS using
    
    ```
    cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On .
    ```
 
* Build and load cl-mbedtls
  * Run `make` in the cl-mbedtls folder

    This should generate the ctypes executable, mbed-ctypes.cl and libmbed_aux.so 
  * Load with ASDF:
  
    ```
    (asdf:load-system :cl-mbedtls)
    ```
    
## ToDo
* Fix memory leaks
* Improve installation process
* Add documentation
* Add hashing APIs
