# BindToC

Allows binding of a C++ object instance's method to a C-style function pointer.


## Description

C libraries callbacks come in two flavours.
 - The tasty one
   Offers a way for the user to pass an abstracted-typed argument to the function to be called in future, generally under the shape of a void pointer.
   You might then cast your precious void pointer into a C++ type and call whatever method you want on your instance.
   However a day will come when you wish you could just pretend your C++ instance's method is a C function, allowing for seamless transition between the C API and your C++ code.

 - The sketchy one
   With no interface for user data, you will be forced to either use globals or statics in order to retrieve informations and trigger actions from the callback.
   You can rely on singleton principles, static mechanics, or even global instances.
   All of these ways have a common issue, we have a single instance -or shared information principle- which might break requirements.


BindToC is a small utility attempting to offer a new approach to the problem, in the form of two options:
 - BindFunctor
   This tool will expect a class with an operator() inside of it and offers a Get method in order to retrieve a corresponding C function pointer.

 - BindMethod
   Allowing you to do exactly what you have always dreamt of ; abstracting an instance's method and the instance itself behind a C function pointer.


This process should be stable and works on the following platforms and environments
- Unis-like systems (x86_64, i386, arm)
- Windows (x64, x32)
- C++ 11, 14, 17, +


## How does it work

Through runtime code writting and modifying, similar to some JIT compiling.

When an instance of a binder class is created, it will allocate N memory pages -platform dependant, will calculate the required size, but usually one- and then proceed to copy some dummy code to that mapped memory area.
This dummy code will then be inspected and modified to have it's matching instance's address written inside, thus when called, it will grab it's instance's target address and then call the matching instance.
The binder instance's is then in possession of the associated C++ instance and able to forward the operator() or method call.


## Issues

/!\ The code behind the C-style function pointer is ONLY available during its binder's lifetime, it will be destroyed uppon its binder own destruction.
/!\ This forbidden art might trigger false positives or even crashes in some debuggers.
/!\ Under ARM based CPUs, if the CPU keeps the binder's instructions running at a critical time, it will NOT refresh its cache as the code is not known to change at runtime, even if it has been modified. This issue is addressed by calling a compiler builtin which in turn will do an inline assembly syscall to trigger the CPU refresh on the modified memory area.
/!\ Return parameter CANNOT be a C++ type calling a non-trivial copy constructor. This might cause undefined behaviour and is thus prohibited at compile time. Returning primitives or pointers is alright.


## Getting started

### Examples

```cpp
#include "BindToC.hpp"

#include <iostream>

struct Object final {
    int Method(std::string const &message) const noexcept {
        std::cout << '\'' << _name << "' " << message << std::endl;
        return 0;
    }

    void operator()(std::string const &message) const noexcept {
        std::cout << message << " '" << _name << '\'' << std::endl;
    }

    std::string const _name;
};

int main(void) noexcept {
    Object const instance1{"foo"}, instance2{"bar"};

    btc::BindFunctor<Object> bindFunctor{instance1}; // Binding on instance1::operator()
    void(*ptr1)(std::string const &){bindFunctor.Get()}; // Use the .Get() method to retrieve the C function pointer

    btc::BindMethod<decltype(&Object::Method)> bindMethod{instance2, &Object::Method}; // Binding on instance2::Method
    int(*ptr2)(std::string const &){bindMethod.Get()}; // Same as above

    // Call the C function pointers
    ptr1("hello from");
    return ptr2("says hi"); // Also returning the value returned from instance2::Method;

}
```

### Installing

This solution is provided as a one header solution, BindToC.hpp is needed, you can copy it to your sources and include it in your code.


## Authors

Ezarkei


## License

This project is licensed under the MIT License -see the LICENSE.md file for details-.