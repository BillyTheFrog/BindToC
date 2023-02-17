/*
// Copyright (c) 2023 Ezarkei
// https://gitlab.com/Ezarkei/BindToC
//
// This document is under the MIT License
*/

#ifndef BINDTOC_HPP_
#define BINDTOC_HPP_

#if ((defined(__i386__) || defined(__x86_64__) || defined(__arm__)) && (defined(__linux__) || defined(__linux) || defined(linux) || defined(__unix__) || defined(__unix))) || (defined(WIN32) || defined(_WIN32) || defined(__WIN32__))

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)
#if defined(_DEBUG) || defined(DEBUG)
#error Requires release compilation (windows)
#endif
#define __win32__
#endif

#ifdef __win32__
#define __attribute__(__)
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#include <cstring>
#endif

#include <type_traits>
#include <stdexcept>
#include <iostream>
#include <string>

#define __FLG__ 0x21626e636967616d
#ifdef __win32__
#define __DCLSPCE__ __declspec(dllexport)
#define __DCLSPCI__ __declspec(dllimport)
#ifdef IMPORT
#define __DCLSPC__ __DCLSPCI__
#else
#define __DCLSPC__ __DCLSPCE__
#endif
#define __DCL__(_) ((decltype(_))(_))
#else
#define __DCLSPCE__
#define __DCLSPCI__
#define __DCLSPC__
#define __DCL__(_) (_)
#endif

namespace btc {

////////////////////////////////////////////////////////////////////////////////

    template<typename R> struct __TTRf__ {
        explicit __TTRf__(void) noexcept = delete;
        using __R__ = R &;
    };

////////////////////////////////////////////////////////////////////////////////

    template<typename R, typename T, typename ...A> class __FcnHldr__ {
    public:
        virtual ~__FcnHldr__(void) noexcept {
        }

        virtual R(*Get(void) const noexcept)(A...) = 0;

    protected:
        explicit __FcnHldr__(void) noexcept {
        }
    };

////////////////////////////////////////////////////////////////////////////////

    template<typename T> struct __XtrctRt__;
    template<typename R, typename T, typename ...A> struct __XtrctRt__<R(T::*)(A...)> {
        using __R__ = R;
    };

////////////////////////////////////////////////////////////////////////////////

    template<typename> class __NtrnlBndMth__;
    template<typename T, typename = typename std::enable_if<std::is_trivially_copy_constructible<typename __XtrctRt__<T>::__R__>::value || std::is_same<typename __XtrctRt__<T>::__R__, void>::value>::type> class __NtrnlBndFcntr__;
    template<typename R, typename T, typename ...A> class __NtrnlBndFcntr__<R(T::*)(A...)> : public __FcnHldr__<R, T, A...> {
    public:
        virtual ~__NtrnlBndFcntr__(void) noexcept;

        virtual R(*Get(void) const noexcept)(A...) override final;

    protected:
        explicit __NtrnlBndFcntr__(T &);

    private:
        R(*_mppr)(__NtrnlBndFcntr__<R(T::*)(A...)> &, typename __TTRf__<A>::__R__...) noexcept = &__MdmMppr__<>;

        void __MplcDdrss__(void const *const);

        template<typename O = R> static typename std::enable_if<std::is_same<O, void>::value, void>::type __MdmMppr__(__NtrnlBndFcntr__<R(T::*)(A...)> &, typename __TTRf__<A>::__R__...) noexcept;
        template<typename O = R> static typename std::enable_if<!std::is_same<O, void>::value, O>::type __MdmMppr__(__NtrnlBndFcntr__<R(T::*)(A...)> &, typename __TTRf__<A>::__R__...) noexcept;
        static std::size_t __PgSzClcltr__(void) noexcept;
        static std::size_t __RwTmpltSzClcltr__(void) noexcept;

        static std::size_t const _flg, _pgSz, _rwTmpltSz, _sgmntSz;
        T &_trgt;
        void *_sgmnt;

        template<typename __R__, typename, typename ...__A__> friend typename std::enable_if<std::is_same<__R__, void>::value, void>::type __SzClcltrE__(__A__...) noexcept;
        template<typename __R__, typename, typename ...__A__> friend typename std::enable_if<!std::is_same<__R__, void>::value, __R__>::type __SzClcltrE__(__A__...) noexcept;
        template<typename __R__, typename, typename ...__A__> friend typename std::enable_if<std::is_same<__R__, void>::value, void>::type __RwTmplt__(__A__...) noexcept;
        template<typename __R__, typename, typename ...__A__> friend typename std::enable_if<!std::is_same<__R__, void>::value, __R__>::type __RwTmplt__(__A__...) noexcept;
        template<typename> friend class __NtrnlBndMth__;
    };

////////////////////////////////////////////////////////////////////////////////

    template<typename> struct __CnstNxcptBstrct__;
    template<typename R, typename T, typename ...A> struct __CnstNxcptBstrct__<R(T::*)(A...)> {
        explicit __CnstNxcptBstrct__(void) noexcept = delete;
        using __T__ = R(T::*)(A...);
    };

    template<typename R, typename T, typename ...A> struct __CnstNxcptBstrct__<R(T::*)(A...) const> {
        explicit __CnstNxcptBstrct__(void) noexcept = delete;
        using __T__ = typename __CnstNxcptBstrct__<R(T::*)(A...)>::__T__;
    };

#if __cplusplus > 201402L
    template<typename R, typename T, typename ...A> struct __CnstNxcptBstrct__<R(T::*)(A...) noexcept> {
        explicit __CnstNxcptBstrct__(void) noexcept = delete;
        using __T__ = typename __CnstNxcptBstrct__<R(T::*)(A...)>::__T__;
    };

    template<typename R, typename T, typename ...A> struct __CnstNxcptBstrct__<R(T::*)(A...) const noexcept> {
        explicit __CnstNxcptBstrct__(void) noexcept = delete;
        using __T__ = typename __CnstNxcptBstrct__<R(T::*)(A...)>::__T__;
    };
#endif

////////////////////////////////////////////////////////////////////////////////

    template<typename T> class __DCLSPC__ __BndFcntr__ final : public __NtrnlBndFcntr__<typename __CnstNxcptBstrct__<decltype(&T::operator())>::__T__> {
    public:
        explicit __BndFcntr__(T &);
        explicit __BndFcntr__(T const &);
        virtual ~__BndFcntr__(void) noexcept override final;
    };

////////////////////////////////////////////////////////////////////////////////

    template<typename> class __NtrnlBndMth__;
    template<typename R, typename T, typename ...A> class __NtrnlBndMth__<R(T::*)(A...)> : public __FcnHldr__<R, T, A...> {
    public:
        virtual ~__NtrnlBndMth__(void) noexcept;

        virtual R(*Get(void) const noexcept)(A...) override final;

    protected:
        explicit __NtrnlBndMth__(T &, R(T::*)(A...));
        explicit __NtrnlBndMth__(T &, R(T::*)(A...) const);
        explicit __NtrnlBndMth__(T const &, R(T::*)(A...) const);

    private:
        template<typename O = R> typename std::enable_if<std::is_same<O, void>::value, void>::type operator()(A...) noexcept;
        template<typename O = R> typename std::enable_if<!std::is_same<O, void>::value, O>::type operator()(A...) noexcept;

        T &_tsdr;
        R(T::*_mth)(A...);
        __NtrnlBndFcntr__<typename __CnstNxcptBstrct__<decltype(&__NtrnlBndMth__<R(T::*)(A...)>::template operator()<>)>::__T__> _lnk{*this};

        friend class __NtrnlBndFcntr__<typename __CnstNxcptBstrct__<decltype(&__NtrnlBndMth__<R(T::*)(A...)>::template operator()<>)>::__T__>;
    };

////////////////////////////////////////////////////////////////////////////////

    template<typename> class __BndMth__;
    template<typename R, typename T, typename ...A> class __DCLSPC__ __BndMth__<R(T::*)(A...)> final : public __NtrnlBndMth__<R(T::*)(A...)> {
    public:
        explicit __BndMth__(T &, R(T::*)(A...));
        virtual ~__BndMth__(void) noexcept override final;
    };

    template<typename R, typename T, typename ...A> class __DCLSPC__ __BndMth__<R(T::*)(A...) const> final : public __NtrnlBndMth__<R(T::*)(A...)> {
    public:
        explicit __BndMth__(T &, R(T::*)(A...) const);
        explicit __BndMth__(T const &, R(T::*)(A...) const);
        virtual ~__BndMth__(void) noexcept override final;
    };

#if __cplusplus > 201402L
    template<typename R, typename T, typename ...A> class __DCLSPC__ __BndMth__<R(T::*)(A...) noexcept> final : public __NtrnlBndMth__<R(T::*)(A...)> {
    public:
        explicit __BndMth__(T &, R(T::*)(A...) noexcept);
        virtual ~__BndMth__(void) noexcept override final;
    };

    template<typename R, typename T, typename ...A> class __DCLSPC__ __BndMth__<R(T::*)(A...) const noexcept> final : public __NtrnlBndMth__<R(T::*)(A...)> {
    public:
        explicit __BndMth__(T &, R(T::*)(A...) const noexcept);
        explicit __BndMth__(T const &, R(T::*)(A...) const noexcept);
        virtual ~__BndMth__(void) noexcept override final;
    };
#endif

////////////////////////////////////////////////////////////////////////////////

    template<typename R, typename T, typename ...A> __attribute__((noinline, optimize(3))) typename std::enable_if<std::is_same<R, void>::value, void>::type __SzClcltrE__(A...) noexcept;
    template<typename R, typename T, typename ...A> __attribute__((noinline, optimize(3))) typename std::enable_if<!std::is_same<R, void>::value, R>::type __SzClcltrE__(A...) noexcept;
    template<typename R, typename T, typename ...A> __attribute__((noinline, optimize(3))) typename std::enable_if<std::is_same<R, void>::value, void>::type __RwTmplt__(A...) noexcept;
    template<typename R, typename T, typename ...A> __attribute__((noinline, optimize(3))) typename std::enable_if<!std::is_same<R, void>::value, R>::type __RwTmplt__(A...) noexcept;

////////////////////////////////////////////////////////////////////////////////

    template<typename R, typename T, typename ...A> __NtrnlBndFcntr__<R(T::*)(A...)>::__NtrnlBndFcntr__(T &trgt) : __FcnHldr__<R, T, A...>{}, _trgt{trgt} {
#ifdef __win32__
        (void const *const)(_rwTmpltSz + _pgSz);
        _sgmnt = VirtualAlloc(NULL, _sgmntSz, MEM_COMMIT, PAGE_READWRITE);
        if (!_sgmnt)
            throw std::runtime_error{std::string{"BindToC :: VirtualAlloc error :: "} + std::to_string(GetLastError())};
#else
        _sgmnt = mmap(nullptr, _sgmntSz, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (MAP_FAILED == _sgmnt)
            throw std::runtime_error{std::string{"BindToC :: Mmap error :: "} + strerror(errno)};
#endif
        void const *const sgmnt{(void const *)__DCL__((&__RwTmplt__<R, T, A...>))};
        std::memcpy(_sgmnt, sgmnt, _rwTmpltSz);
        __MplcDdrss__(this);
#ifdef __win32__
        unsigned long dscrd;
        if (!VirtualProtect(_sgmnt, _sgmntSz, PAGE_EXECUTE_READ, &dscrd))
            throw std::runtime_error{std::string{"BindToC :: VirtualProtect error :: "} + std::to_string(GetLastError())};
#else
        if (mprotect(_sgmnt, _sgmntSz, PROT_EXEC | PROT_READ))
            throw std::runtime_error{std::string{"BindToC :: Mprotect error :: "} + strerror(errno)};
        __builtin___clear_cache((char *)_sgmnt, (char *)_sgmnt + _rwTmpltSz);
#endif
    }

    template<typename R, typename T, typename ...A> __NtrnlBndFcntr__<R(T::*)(A...)>::~__NtrnlBndFcntr__(void) noexcept {
#ifdef __win32__
        if (!VirtualFree(_sgmnt, 0, MEM_RELEASE))
#else
            if (munmap(_sgmnt, _sgmntSz))
#endif
            {
                std::cerr << "BindToC :: Memory release failed :: Aborting" << std::endl;
                abort();
            }
    }

    template<typename R, typename T, typename ...A> R(*__NtrnlBndFcntr__<R(T::*)(A...)>::Get(void) const noexcept)(A...) {
        return (R(*)(A...))_sgmnt;
    }

    template<typename R, typename T, typename ...A> void __NtrnlBndFcntr__<R(T::*)(A...)>::__MplcDdrss__(void const *const ddrss) {
        std::size_t const tht((std::size_t const)ddrss);
        uint8_t *ffst{nullptr}, m{0};
        for (std::size_t i{0}, j{0}, k{0}; !ffst && _rwTmpltSz > i; ++i)
            if (j[(uint8_t*)&_flg] == i[(uint8_t*)_sgmnt]) {
                if (!j++)
                    k = i;
                else if (sizeof(void *volatile const) <= j)
                    ffst = (uint8_t*)_sgmnt + k;
            } else if (j)
                j = 0;
        if (ffst)
            std::memcpy(ffst, &tht, sizeof(void *volatile const));
        else {
            for (std::size_t i{0}; !ffst && _rwTmpltSz > i; ++i)
                for (uint8_t l{0}; !ffst && 8 > l; l += 4)
                    for (std::size_t j{0}, k{0}; _rwTmpltSz > i + j + k && 7 > j; 2 == j ? (j += 2, k = l) : ++j)
                        if (!(j % 4 ? j % 2 ? (uint8_t{(uint8_t)(j[(uint8_t *)_sgmnt + i + k] << 4)} >> 4) == uint8_t{(uint8_t)((j / 4 ? 3 : 1)[(uint8_t *)&_flg] << 4)} >> 4 : (uint8_t{(uint8_t)(j[(uint8_t *)_sgmnt + i + k] << 4)} >> 4) == (j / 4 ? 3 : 1)[(uint8_t *)&_flg] >> 4 : j[(uint8_t *)_sgmnt + i + k] == (j / 2)[(uint8_t *)&_flg]))
                            j = 7;
                        else if (6 == j) {
                            ffst = (uint8_t *)_sgmnt + i;
                            m = l;
                        }
            if (ffst)
                for (std::size_t i{0}, k{0}; 7 > i; 2 == i ? (i += 2, k = m) : ++i)
                    i % 4 ? ((i[ffst + k] >>= 4) <<= 4) |= i % 2 ? uint8_t{(uint8_t)((i / 4 ? 3 : 1)[(uint8_t *)&tht] << 4)} >> 4 : (i / 4 ? 3 : 1)[(uint8_t *)&tht] >> 4 : i[ffst + k] = (i / 2)[(uint8_t *)&tht];
        }
        if (!ffst)
            throw std::runtime_error{"BindToC :: Failed to resolve flag offset"};
    }

    template<typename R, typename T, typename ...A> template<typename O> typename std::enable_if<std::is_same<O, void>::value, void>::type __NtrnlBndFcntr__<R(T::*)(A...)>::__MdmMppr__(__NtrnlBndFcntr__<R(T::*)(A...)> &tht, typename __TTRf__<A>::__R__... flds) noexcept {
        tht._trgt.operator()(std::forward<A>(flds)...);
    }

    template<typename R, typename T, typename ...A> template<typename O> typename std::enable_if<!std::is_same<O, void>::value, O>::type __NtrnlBndFcntr__<R(T::*)(A...)>::__MdmMppr__(__NtrnlBndFcntr__<R(T::*)(A...)> &tht, typename __TTRf__<A>::__R__... flds) noexcept {
        return tht._trgt.operator()(std::forward<A>(flds)...);
    }

////////////////////////////////////////////////////////////////////////////////

    template<typename R, typename T, typename ...A> std::size_t __NtrnlBndFcntr__<R(T::*)(A...)>::__PgSzClcltr__(void) noexcept {
#ifdef __win32__
        SYSTEM_INFO nf{};
        GetSystemInfo(&nf);
        return nf.dwPageSize;
#else
        return (std::size_t)sysconf(_SC_PAGESIZE);
#endif
    }

    template<typename R, typename T, typename ...A> std::size_t __NtrnlBndFcntr__<R(T::*)(A...)>::__RwTmpltSzClcltr__(void) noexcept {
        if ((std::size_t)__DCL__((&__RwTmplt__<R, T, A...>)) > (std::size_t)__DCL__((&__SzClcltrE__<R, T, A...>)));
        std::size_t const size{(std::size_t)__DCL__((&__SzClcltrE__<R, T, A...>)) > (std::size_t)__DCL__((&__RwTmplt__<R, T, A...>)) ? (std::size_t)__DCL__((&__SzClcltrE__<R, T, A...>)) - (std::size_t)__DCL__((&__RwTmplt__<R, T, A...>)) : (std::size_t)__DCL__((&__RwTmplt__<R, T, A...>)) - (std::size_t)__DCL__((&__SzClcltrE__<R, T, A...>))};
        if (!size) {
            std::cerr << "BindToC :: Memory order failed :: Unsupported architecture or compiler :: Aborting" << std::endl;
            abort();
        }
        return size;
    }

    template<typename R, typename T, typename ...A> std::size_t const __NtrnlBndFcntr__<R(T::*)(A...)>::_flg((std::size_t)__FLG__);

    template<typename R, typename T, typename ...A> std::size_t const __NtrnlBndFcntr__<R(T::*)(A...)>::_pgSz{__PgSzClcltr__()};

    template<typename R, typename T, typename ...A> std::size_t const __NtrnlBndFcntr__<R(T::*)(A...)>::_rwTmpltSz{__RwTmpltSzClcltr__()};

    template<typename R, typename T, typename ...A> std::size_t const __NtrnlBndFcntr__<R(T::*)(A...)>::_sgmntSz{(_rwTmpltSz / _pgSz + 1) * _pgSz};

////////////////////////////////////////////////////////////////////////////////

    template<typename T> __BndFcntr__<T>::__BndFcntr__(T &trgt) : __NtrnlBndFcntr__<typename __CnstNxcptBstrct__<decltype(&T::operator())>::__T__>{trgt} {
    }

    template<typename T> __BndFcntr__<T>::__BndFcntr__(T const &trgt) : __NtrnlBndFcntr__<typename __CnstNxcptBstrct__<decltype(&T::operator())>::__T__>{const_cast<T &>(trgt)} {
    }

    template<typename T> __BndFcntr__<T>::~__BndFcntr__(void) noexcept {
    }

////////////////////////////////////////////////////////////////////////////////

    template<typename R, typename T, typename ...A> __NtrnlBndMth__<R(T::*)(A...)>::__NtrnlBndMth__(T &tsdr, R(T::*mth)(A...)) : __FcnHldr__<R, T, A...>{}, _tsdr{tsdr}, _mth{mth} {
    }

    template<typename R, typename T, typename ...A> __NtrnlBndMth__<R(T::*)(A...)>::__NtrnlBndMth__(T &tsdr, R(T::*mth)(A...) const) : __FcnHldr__<R, T, A...>{}, _tsdr{tsdr}, _mth{(R(T::*)(A...))(mth)} {
    }

    template<typename R, typename T, typename ...A> __NtrnlBndMth__<R(T::*)(A...)>::__NtrnlBndMth__(T const &tsdr, R(T::*mth)(A...) const) : __FcnHldr__<R, T, A...>{}, _tsdr{const_cast<T &>(tsdr)}, _mth{(R(T::*)(A...))(mth)} {
    }

    template<typename R, typename T, typename ...A> __NtrnlBndMth__<R(T::*)(A...)>::~__NtrnlBndMth__(void) noexcept {
    }

    template<typename R, typename T, typename ...A> R(*__NtrnlBndMth__<R(T::*)(A...)>::Get(void) const noexcept)(A...) {
        return _lnk.Get();
    }

    template<typename R, typename T, typename ...A> template<typename O> typename std::enable_if<std::is_same<O, void>::value, void>::type __NtrnlBndMth__<R(T::*)(A...)>::operator()(A... flds) noexcept {
        (_tsdr.*_mth)(std::forward<A>(flds)...);
    }

    template<typename R, typename T, typename ...A> template<typename O> typename std::enable_if<!std::is_same<O, void>::value, O>::type __NtrnlBndMth__<R(T::*)(A...)>::operator()(A... flds) noexcept {
        return (_tsdr.*_mth)(std::forward<A>(flds)...);
    }

////////////////////////////////////////////////////////////////////////////////

    template<typename R, typename T, typename ...A> __BndMth__<R(T::*)(A...)>::__BndMth__(T &tsdr, R(T::*mth)(A...)) : __NtrnlBndMth__<R(T::*)(A...)>{tsdr, mth} {
    }

    template<typename R, typename T, typename ...A> __BndMth__<R(T::*)(A...)>::~__BndMth__(void) noexcept {
    }

    template<typename R, typename T, typename ...A> __BndMth__<R(T::*)(A...) const>::__BndMth__(T &tsdr, R(T::*mth)(A...) const) : __NtrnlBndMth__<R(T::*)(A...)>{tsdr, mth} {
    }

    template<typename R, typename T, typename ...A> __BndMth__<R(T::*)(A...) const>::__BndMth__(T const &tsdr, R(T::*mth)(A...) const) : __NtrnlBndMth__<R(T::*)(A...)>{tsdr, mth} {
    }

    template<typename R, typename T, typename ...A> __BndMth__<R(T::*)(A...) const>::~__BndMth__(void) noexcept {
    }

#if __cplusplus > 201402L
    template<typename R, typename T, typename ...A> __BndMth__<R(T::*)(A...) noexcept>::__BndMth__(T &tsdr, R(T::*mth)(A...) noexcept) : __NtrnlBndMth__<R(T::*)(A...)>{tsdr, mth} {
    }

    template<typename R, typename T, typename ...A> __BndMth__<R(T::*)(A...) noexcept>::~__BndMth__(void) noexcept {
    }

    template<typename R, typename T, typename ...A> __BndMth__<R(T::*)(A...) const noexcept>::__BndMth__(T &tsdr, R(T::*mth)(A...) const noexcept) : __NtrnlBndMth__<R(T::*)(A...)>{tsdr, mth} {
    }

    template<typename R, typename T, typename ...A> __BndMth__<R(T::*)(A...) const noexcept>::__BndMth__(T const &tsdr, R(T::*mth)(A...) const noexcept) : __NtrnlBndMth__<R(T::*)(A...)>{tsdr, mth} {
    }

    template<typename R, typename T, typename ...A> __BndMth__<R(T::*)(A...) const noexcept>::~__BndMth__(void) noexcept {
    }
#endif

////////////////////////////////////////////////////////////////////////////////

    template<typename R, typename T, typename ...A> typename std::enable_if<std::is_same<R, void>::value, void>::type __SzClcltrE__(A... __flds__) noexcept {
        void *volatile const __rwTmpltRmPtr__{(void *)(__FLG__ ^ __FLG__)};
        __NtrnlBndFcntr__<R(T::*)(A...)> &tht{*((__NtrnlBndFcntr__<R(T::*)(A...)> *const)__rwTmpltRmPtr__)};
        (*tht._mppr)(tht, __flds__...);
    }

    template<typename R, typename T, typename ...A> typename std::enable_if<!std::is_same<R, void>::value, R>::type __SzClcltrE__(A... __flds__) noexcept {
        void *volatile const __rwTmpltRmPtr__{(void *)(__FLG__ ^ __FLG__)};
        __NtrnlBndFcntr__<R(T::*)(A...)> &tht{*((__NtrnlBndFcntr__<R(T::*)(A...)> *const)__rwTmpltRmPtr__)};
        return (*tht._mppr)(tht, __flds__...);
    }

    template<typename R, typename T, typename ...A> typename std::enable_if<std::is_same<R, void>::value, void>::type __RwTmplt__(A... __flds__) noexcept {
        void *volatile const __rwTmpltRmPtr__{(void *)__FLG__};
        __NtrnlBndFcntr__<R(T::*)(A...)> &tht{*((__NtrnlBndFcntr__<R(T::*)(A...)> *const)__rwTmpltRmPtr__)};
        (*tht._mppr)(tht, __flds__...);
    }

    template<typename R, typename T, typename ...A> typename std::enable_if<!std::is_same<R, void>::value, R>::type __RwTmplt__(A... __flds__) noexcept {
        void *volatile const __rwTmpltRmPtr__{(void *)__FLG__};
        __NtrnlBndFcntr__<R(T::*)(A...)> &tht{*((__NtrnlBndFcntr__<R(T::*)(A...)> *const)__rwTmpltRmPtr__)};
        return (*tht._mppr)(tht, __flds__...);
    }

////////////////////////////////////////////////////////////////////////////////

    template<typename T> using BindFunctor = __BndFcntr__<T>;
    template<typename T> using BindMethod = __BndMth__<T>;

////////////////////////////////////////////////////////////////////////////////

}

#ifdef __win32__
#undef __win32__
#undef __attribute__
#endif
#undef __DCL__
#undef __FLG__
#undef __DCLSPCE__
#undef __DCLSPCI__
#undef __DCLSPC__

#else
#error Unknown architecture ; supports unix(-like) (x86_64, i386, arm) and windows (x64, x32)
#endif
#endif
