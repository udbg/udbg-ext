
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <DbgEng.h>

#define EXTERN extern "C"

#define DbgClient IDebugClient5
#define DbgControl IDebugControl4
#define DbgSpaces IDebugDataSpaces4
#define DbgRegs IDebugRegisters2
#define DbgSyms IDebugSymbols3
#define DbgSysobj IDebugSystemObjects4
#define DbgAdv IDebugAdvanced

typedef void *Adaptor;

struct WinDbg {
    DbgClient *client;
    DbgControl *ctrl;
    DbgSpaces *spaces;
    DbgRegs *regs;
    DbgSyms *syms;
    DbgSysobj *sysobj;
    DbgAdv *adv;
};

EXTERN void udbg_output(Adaptor ui, ULONG, PCWSTR);
EXTERN void udbg_set_pid_tid(Adaptor ui, size_t pid, size_t tid);
EXTERN HRESULT udbg_on_exception(Adaptor ui, bool first, ULONG code);
EXTERN HRESULT udbg_on_breakpoint(Adaptor ui, IDebugBreakpoint2 *bp);
EXTERN HRESULT udbg_on_engine_state(Adaptor ui, ULONG flags, ULONG64 state);
EXTERN HRESULT udbg_on_load_module(Adaptor ui, size_t base, size_t size, PCWSTR, PCWSTR);
EXTERN HRESULT udbg_on_unload_module(Adaptor ui, PCWSTR ImageBaseName, ULONG64 BaseOffset);
EXTERN HRESULT udbg_on_thread_create(Adaptor ui, ULONG64 Handle, ULONG64 DataOffset, ULONG64 StartOffset);
EXTERN HRESULT udbg_on_thread_exit(Adaptor ui, ULONG code);
EXTERN HRESULT udbg_on_create_process(Adaptor ui, ULONG64 ImageFileHandle, ULONG64 Handle, ULONG64 BaseOffset, ULONG ModuleSize, PCWSTR ModuleName, PCWSTR ImageName, ULONG CheckSum, ULONG TimeDateStamp, ULONG64 InitialThreadHandle, ULONG64 ThreadDataOffset, ULONG64 StartOffset);
EXTERN HRESULT udbg_on_process_exit(Adaptor ui, ULONG code);

class InputCallback : public IDebugInputCallbacks {
public:
    InputCallback(Adaptor ui, WinDbg *dbg): ui(ui), ctrl(dbg->ctrl) {}

    virtual ULONG _stdcall AddRef() { return 0; }
    virtual ULONG _stdcall Release() { return 1; }
    virtual HRESULT _stdcall QueryInterface(REFIID id, void **pp)
    {
        *pp = NULL;
        if (IsEqualIID(id, __uuidof(IUnknown)) ||
            IsEqualIID(id, __uuidof(IDebugInputCallbacks))) {
            *pp = this, AddRef();
            return S_OK;
        }
        else
            return E_NOINTERFACE;
    }

    static bool isinputting;

    virtual HRESULT _stdcall StartInput(ULONG bufsize)
    {
        printf("[start input]\n");
        return S_OK;
    }

    virtual HRESULT _stdcall EndInput()
    {
        printf("[end input]\n");
        return S_OK;
    }

private:
    Adaptor ui;
    DbgControl *ctrl;
};

class OutputCallback : public IDebugOutputCallbacksWide
{
public:
    OutputCallback(Adaptor ui): ui(ui) {}

    virtual ULONG _stdcall AddRef() { return 0; }
    virtual ULONG _stdcall Release() { return 1; }
    virtual HRESULT _stdcall QueryInterface(REFIID id, void **pp) {
        *pp = NULL;
        if (IsEqualIID(id, __uuidof(IUnknown)) ||
            IsEqualIID(id, __uuidof(IDebugOutputCallbacks))) {
            *pp = this, AddRef();
            return S_OK;
        } else
            return E_NOINTERFACE;
    }

    virtual HRESULT _stdcall Output(IN ULONG Mask, IN PCWSTR Text)
    {
        udbg_output(ui, Mask, Text);
        return S_OK;
    }

private:
    Adaptor ui;
};

class EventCallback : public IDebugEventCallbacksWide
{
public:
    EventCallback(Adaptor ui, DbgSysobj *sobj): ui(ui), sobj(sobj) {}

    virtual ULONG _stdcall AddRef() { return 0; }
    virtual ULONG _stdcall Release() { return 1; }
    virtual HRESULT _stdcall QueryInterface(REFIID id, void **ppvObj)
    {
        *ppvObj = this;
        return NOERROR;
    }

    virtual HRESULT _stdcall GetInterestMask(PULONG Mask)
    {
        *Mask =
            DEBUG_EVENT_BREAKPOINT |
            DEBUG_EVENT_LOAD_MODULE |
            DEBUG_EVENT_EXCEPTION |
            DEBUG_EVENT_CREATE_THREAD |
            DEBUG_EVENT_EXIT_THREAD |
            DEBUG_EVENT_CREATE_PROCESS |
            DEBUG_EVENT_EXIT_PROCESS |
            DEBUG_EVENT_UNLOAD_MODULE |
            DEBUG_EVENT_SYSTEM_ERROR |
            DEBUG_EVENT_SESSION_STATUS |
            DEBUG_EVENT_CHANGE_DEBUGGEE_STATE |
            DEBUG_EVENT_CHANGE_ENGINE_STATE |
            DEBUG_EVENT_CHANGE_SYMBOL_STATE;
        return S_OK;
    }

    virtual HRESULT _stdcall Breakpoint(IDebugBreakpoint2 *bp)
    {
        return udbg_on_breakpoint(ui, bp);
    }

    virtual HRESULT _stdcall ChangeDebuggeeState(ULONG Flags, ULONG64 Argument)
    {
        // printf("ChangeDebuggeeState: %d %p\n", Flags, Argument);
        return DEBUG_STATUS_GO_NOT_HANDLED;
    }
    virtual HRESULT _stdcall ChangeEngineState(ULONG Flags, ULONG64 Argument)
    {
        return udbg_on_engine_state(ui, Flags, Argument);
    }
    virtual HRESULT _stdcall Exception(PEXCEPTION_RECORD64 Exception, ULONG FirstChance)
    {
        return udbg_on_exception(ui, FirstChance, Exception->ExceptionCode);
    }
    virtual HRESULT _stdcall LoadModule(
        _In_ ULONG64 ImageFileHandle,
        _In_ ULONG64 BaseOffset,
        _In_ ULONG ModuleSize,
        _In_opt_ PCWSTR ModuleName,
        _In_opt_ PCWSTR ImageName,
        _In_ ULONG CheckSum,
        _In_ ULONG TimeDateStamp
    )
    {
        return udbg_on_load_module(ui, BaseOffset, ModuleSize, ModuleName, ImageName);
    }
    virtual HRESULT _stdcall UnloadModule(PCWSTR ImageBaseName, ULONG64 BaseOffset)
    {
        return udbg_on_unload_module(ui, ImageBaseName, BaseOffset);
    }
    virtual HRESULT _stdcall ExitProcess(ULONG ExitCode)
    {
        return udbg_on_process_exit(ui, ExitCode);
    }
    virtual HRESULT _stdcall SessionStatus(ULONG Status)
    {
        printf("SessionStatus: %x\n", Status);
        return DEBUG_STATUS_GO_NOT_HANDLED;
    }
    virtual HRESULT _stdcall ChangeSymbolState(ULONG Flags, ULONG64 Argument)
    {
        printf("ChangeSymbolState: %x %x\n", Flags, Argument);
        return DEBUG_STATUS_GO_NOT_HANDLED;
    }
    virtual HRESULT _stdcall SystemError(ULONG Error, ULONG Level)
    {
        return DEBUG_STATUS_GO_NOT_HANDLED;
    }
    virtual HRESULT _stdcall CreateThread(ULONG64 Handle, ULONG64 DataOffset, ULONG64 StartOffset)
    {
        return udbg_on_thread_create(ui, Handle, DataOffset, StartOffset);
    }
    virtual HRESULT _stdcall ExitThread(ULONG ExitCode)
    {
        return udbg_on_thread_exit(ui, ExitCode);
    }

    virtual HRESULT _stdcall CreateProcess(
        _In_ ULONG64 ImageFileHandle,
        _In_ ULONG64 Handle,
        _In_ ULONG64 BaseOffset,
        _In_ ULONG ModuleSize,
        _In_opt_ PCWSTR ModuleName,
        _In_opt_ PCWSTR ImageName,
        _In_ ULONG CheckSum,
        _In_ ULONG TimeDateStamp,
        _In_ ULONG64 InitialThreadHandle,
        _In_ ULONG64 ThreadDataOffset,
        _In_ ULONG64 StartOffset
    )
    {
        return udbg_on_create_process(ui,
            ImageFileHandle,
            Handle,
            BaseOffset,
            ModuleSize,
            ModuleName,
            ImageName,
            CheckSum,
            TimeDateStamp,
            InitialThreadHandle,
            ThreadDataOffset,
            StartOffset
        );
    }

private:
    Adaptor ui;
    DbgSysobj *sobj;
};

typedef HRESULT (*FnDebugCreate)(REFIID InterfaceId, PVOID* Interface);
EXTERN size_t wdbg_new(HMODULE hmod, WinDbg *self)
{
    auto DebugCreate_ = (FnDebugCreate)GetProcAddress(hmod, "DebugCreate");
    auto r = DebugCreate_(__uuidof(DbgClient), (void **)&self->client);
    assert(r == S_OK);
    r = self->client->QueryInterface(__uuidof(DbgControl), (void **)&self->ctrl);
    assert(r == S_OK);
    r = self->client->QueryInterface(__uuidof(DbgRegs), (void **)&self->regs);
    assert(r == S_OK);
    r = self->client->QueryInterface(__uuidof(DbgSpaces), (void **)&self->spaces);
    assert(r == S_OK);
    r = self->client->QueryInterface(__uuidof(DbgSyms), (void **)&self->syms);
    assert(r == S_OK);
    r = self->client->QueryInterface(__uuidof(DbgSysobj), (void **)&self->sysobj);
    assert(r == S_OK);
    r = self->client->QueryInterface(__uuidof(DbgAdv), (void **)&self->adv);
    assert(r == S_OK);
    self->ctrl->AddEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK | DEBUG_ENGOPT_FINAL_BREAK);
    self->ctrl->SetInterruptTimeout(1);
    return 0;
}

EXTERN void wdbg_init_callback(WinDbg *self, Adaptor a)
{
    self->client->SetInputCallbacks(new InputCallback(a, self));
    self->client->SetOutputCallbacksWide(new OutputCallback(a));
    self->client->SetEventCallbacksWide(new EventCallback(a, self->sysobj));
}

EXTERN size_t wdbg_read(DbgSpaces *self, size_t address, uint8_t *out, size_t size)
{
    ULONG result = 0;
    auto r = self->ReadVirtual(address, out, size, &result);
    return S_OK == r ? result : 0;
}

EXTERN size_t wdbg_write(DbgSpaces *self, size_t address, const uint8_t *data, size_t size)
{
    ULONG result = 0;
    auto r = self->WriteVirtual(address, (PVOID)data, size, &result);
    return S_OK == r ? result : 0;
}

EXTERN size_t wdbg_attach_process(DbgClient *self, size_t pid)
{
    return self->AttachProcess(NULL, pid, DEBUG_ATTACH_INVASIVE_RESUME_PROCESS);
}

EXTERN void wdbg_break(DbgControl *self)
{
    self->SetInterrupt(DEBUG_INTERRUPT_ACTIVE);
}

EXTERN bool wdbg_query_virtual(DbgSpaces *self, size_t address, PMEMORY_BASIC_INFORMATION64 info)
{
    return self->QueryVirtual(address, info) == S_OK;
}

EXTERN size_t wdbg_current_thread(DbgSysobj *self)
{
    ULONG n;
    return S_OK == self->GetCurrentThreadSystemId(&n) ? n : 0;
}

EXTERN size_t wdbg_current_process(DbgSysobj *self)
{
    ULONG n;
    return S_OK == self->GetCurrentProcessSystemId(&n) ? n : 0;
}

EXTERN size_t wdbg_module_count(DbgSyms *self)
{
    ULONG n, n1;
    return S_OK == self->GetNumberModules(&n, &n1) ? n + n1 : 0;
}

EXTERN bool wdbg_module_infos(DbgSyms *self, PDEBUG_MODULE_PARAMETERS infos, size_t i, size_t count)
{
    return S_OK == self->GetModuleParameters(count, NULL, i, infos);
}

EXTERN size_t wdbg_find_module(DbgSyms *self, size_t a, PULONG i)
{
    ULONG64 base = 0;
    self->GetModuleByOffset(a, 0, i, &base);
    return base;
}

EXTERN size_t wdbg_get_module(DbgSyms *self, PCWSTR m, PULONG i)
{
    ULONG64 base = 0;
    self->GetModuleByModuleNameWide(m, 0, i, &base);
    return base;
}

EXTERN size_t wdbg_get_near_name(DbgSyms *self, size_t a, size_t max, PSTR buf, size_t size, uint64_t *disp)
{
    ULONG outsize = 0;
    ULONG64 d = 0;
    // self->GetNearNameByOffset(a, max, buf, size, &outsize, disp);
    if (S_OK != self->GetNameByOffset(a, buf, size, &outsize, &d))
        return 0;
    if (disp) *disp = d;
    if (max == 0 && d != 0)
        return 0;
    return outsize;
}

EXTERN size_t wdbg_get_offset(DbgSyms *self, PCWSTR name)
{
    ULONG64 address = 0;
    self->GetOffsetByNameWide(name, &address);
    return address;
}

EXTERN size_t wdbg_evaluate(DbgControl *self, PCWSTR name)
{
    DEBUG_VALUE v;
    return S_OK == self->EvaluateWide(name, DEBUG_VALUE_INT64, &v, NULL) ? v.I64 : 0;
}

EXTERN void wdbg_set_status(DbgControl *self, ULONG status)
{
    self->SetExecutionStatus(status);
}

EXTERN size_t wdbg_wait_event(DbgControl *self)
{
    return self->WaitForEvent(0, INFINITE);
}

EXTERN size_t wdbg_get_reg_name(DbgRegs *self, size_t i, char *name, size_t size)
{
    return self->GetDescription(i, name, size, NULL, NULL);
}

EXTERN size_t wdbg_get_registers(DbgAdv *self, CONTEXT *context)
{
    return self->GetThreadContext(context, sizeof(CONTEXT));
}

EXTERN size_t wdbg_get_reg(DbgRegs *self, size_t i, size_t *v)
{
    DEBUG_VALUE val;
    auto r = self->GetValue(i, &val);
    *v = val.I64;
    return r;
}

EXTERN size_t wdbg_set_reg(DbgRegs *self, size_t i, size_t v)
{
    DEBUG_VALUE val;
    val.I64 = v;
    return self->SetValue(i, &val);
}