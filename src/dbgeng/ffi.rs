
use winapi::{shared::minwindef::*, um::winnt::*};

pub const DEBUG_ANY_ID: u32 = 0xffffffff;

pub const DEBUG_MODNAME_IMAGE:        u32 = 0x00000000;
pub const DEBUG_MODNAME_MODULE:       u32 = 0x00000001;
pub const DEBUG_MODNAME_LOADED_IMAGE: u32 = 0x00000002;
pub const DEBUG_MODNAME_SYMBOL_FILE:  u32 = 0x00000003;
pub const DEBUG_MODNAME_MAPPED_IMAGE: u32 = 0x00000004;

pub const DEBUG_MODULE_LOADED: u32            = 0x00000000;
pub const DEBUG_MODULE_UNLOADED: u32          = 0x00000001;
pub const DEBUG_MODULE_USER_MODE: u32         = 0x00000002;
pub const DEBUG_MODULE_EXE_MODULE: u32        = 0x00000004;
pub const DEBUG_MODULE_EXPLICIT: u32          = 0x00000008;
pub const DEBUG_MODULE_SECONDARY: u32         = 0x00000010;
pub const DEBUG_MODULE_SYNTHETIC: u32         = 0x00000020;
pub const DEBUG_MODULE_SYM_BAD_CHECKSUM: u32  = 0x00010000;

pub const DEBUG_SYMTYPE_NONE: u32     = 0;
pub const DEBUG_SYMTYPE_COFF: u32     = 1;
pub const DEBUG_SYMTYPE_CODEVIEW: u32 = 2;
pub const DEBUG_SYMTYPE_PDB: u32      = 3;
pub const DEBUG_SYMTYPE_EXPORT: u32   = 4;
pub const DEBUG_SYMTYPE_DEFERRED: u32 = 5;
pub const DEBUG_SYMTYPE_SYM: u32      = 6;
pub const DEBUG_SYMTYPE_DIA: u32      = 7;

pub const DEBUG_CES_ALL: u32                  = 0xffffffff;
pub const DEBUG_CES_CURRENT_THREAD: u32       = 0x00000001;
pub const DEBUG_CES_EFFECTIVE_PROCESSOR: u32  = 0x00000002;
pub const DEBUG_CES_BREAKPOINTS: u32          = 0x00000004;
pub const DEBUG_CES_CODE_LEVEL: u32           = 0x00000008;
pub const DEBUG_CES_EXECUTION_STATUS: u32     = 0x00000010;
pub const DEBUG_CES_ENGINE_OPTIONS: u32       = 0x00000020;
pub const DEBUG_CES_LOG_FILE: u32             = 0x00000040;
pub const DEBUG_CES_RADIX: u32                = 0x00000080;
pub const DEBUG_CES_EVENT_FILTERS: u32        = 0x00000100;
pub const DEBUG_CES_PROCESS_OPTIONS: u32      = 0x00000200;
pub const DEBUG_CES_EXTENSIONS: u32           = 0x00000400;
pub const DEBUG_CES_SYSTEMS: u32              = 0x00000800;
pub const DEBUG_CES_ASSEMBLY_OPTIONS: u32     = 0x00001000;
pub const DEBUG_CES_EXPRESSION_SYNTAX: u32    = 0x00002000;
pub const DEBUG_CES_TEXT_REPLACEMENTS: u32    = 0x00004000;
pub const DEBUG_CSS_ALL: u32             = 0xffffffff;
pub const DEBUG_CSS_LOADS: u32           = 0x00000001;
pub const DEBUG_CSS_UNLOADS: u32         = 0x00000002;
pub const DEBUG_CSS_SCOPE: u32           = 0x00000004;
pub const DEBUG_CSS_PATHS: u32           = 0x00000008;
pub const DEBUG_CSS_SYMBOL_OPTIONS: u32  = 0x00000010;
pub const DEBUG_CSS_TYPE_OPTIONS: u32    = 0x00000020;
pub const DEBUG_CSS_COLLAPSE_CHILDREN: u32  = 0x00000040;

pub const DEBUG_DATA_SPACE_VIRTUAL: u32       = 0;
pub const DEBUG_DATA_SPACE_PHYSICAL: u32      = 1;
pub const DEBUG_DATA_SPACE_CONTROL: u32       = 2;
pub const DEBUG_DATA_SPACE_IO: u32            = 3;
pub const DEBUG_DATA_SPACE_MSR: u32           = 4;
pub const DEBUG_DATA_SPACE_BUS_DATA: u32      = 5;
pub const DEBUG_DATA_SPACE_DEBUGGER_DATA: u32 = 6;
pub const DEBUG_DATA_SPACE_COUNT: u32         = 7;

pub const DEBUG_OFFSINFO_VIRTUAL_SOURCE: u32 = 0x00000001;

pub const DEBUG_VSOURCE_INVALID: u32              = 0x00000000;
pub const DEBUG_VSOURCE_DEBUGGEE: u32             = 0x00000001;
pub const DEBUG_VSOURCE_MAPPED_IMAGE: u32         = 0x00000002;
pub const DEBUG_VSOURCE_DUMP_WITHOUT_MEMINFO: u32 = 0x00000003;

pub const DEBUG_VSEARCH_DEFAULT: u32       = 0x00000000;
pub const DEBUG_VSEARCH_WRITABLE_ONLY: u32 = 0x00000001;

pub const DEBUG_PHYSICAL_DEFAULT: u32        = 0x00000000;
pub const DEBUG_PHYSICAL_CACHED: u32         = 0x00000001;
pub const DEBUG_PHYSICAL_UNCACHED: u32       = 0x00000002;
pub const DEBUG_PHYSICAL_WRITE_COMBINED: u32 = 0x00000003;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DEBUG_MODULE_PARAMETERS {
    pub Base: u64,
    pub Size: ULONG,
    pub TimeDateStamp: ULONG,
    pub Checksum: ULONG,
    pub Flags: ULONG,
    pub SymbolType: ULONG,
    pub ImageNameSize: ULONG,
    pub ModuleNameSize: ULONG,
    pub LoadedImageNameSize: ULONG,
    pub SymbolFileNameSize: ULONG,
    pub MappedImageNameSize: ULONG,
    pub Reserved: [u64; 2],
}

#[repr(C)]
pub struct IUnknown {
    QueryInterface: usize,
    AddRef: usize,
    Release: usize,
}

#[repr(C)]
pub struct IDebugSymbols3_VTable {
    pub base: IUnknown,
    pub GetSymbolOptions: usize,
    pub AddSymbolOptions: usize,
    pub RemoveSymbolOptions: usize,
    pub SetSymbolOptions: usize,
    pub GetNameByOffset: usize,
    pub GetOffsetByName: usize,
    pub GetNearNameByOffset: usize,
    pub GetLineByOffset: usize,
    pub GetOffsetByLine: usize,
    pub GetNumberModules: usize,
    pub GetModuleByIndex: usize,
    pub GetModuleByModuleName: usize,
    pub GetModuleByOffset: extern "system" fn(&DbgSyms, Offset: u64, StartIndex: ULONG, Index: PULONG, Base: *mut u64) -> HRESULT,
    pub GetModuleNames: usize,
    pub GetModuleParameters: extern "system" fn(&DbgSyms, Count: ULONG, Bases: *const u64, Start: u32, Params: *mut DEBUG_MODULE_PARAMETERS) -> HRESULT,
    pub GetSymbolModule: usize,
    pub GetTypeName: usize,
    pub GetTypeId: usize,
    pub GetTypeSize: usize,
    pub GetFieldOffset: usize,
    pub GetSymbolTypeId: usize,
    pub GetOffsetTypeId: usize,
    pub ReadTypedDataVirtual: usize,
    pub WriteTypedDataVirtual: usize,
    pub OutputTypedDataVirtual: usize,
    pub ReadTypedDataPhysical: usize,
    pub WriteTypedDataPhysical: usize,
    pub OutputTypedDataPhysical: usize,
    pub GetScope: usize,
    pub SetScope: usize,
    pub ResetScope: usize,
    pub GetScopeSymbolGroup: usize,
    pub CreateSymbolGroup: usize,
    pub StartSymbolMatch: usize,
    pub GetNextSymbolMatch: usize,
    pub EndSymbolMatch: extern "system" fn(&DbgSyms, u64) -> HRESULT,
    pub Reload: usize,
    pub GetSymbolPath: usize,
    pub SetSymbolPath: usize,
    pub AppendSymbolPath: usize,
    pub GetImagePath: usize,
    pub SetImagePath: usize,
    pub AppendImagePath: usize,
    pub GetSourcePath: usize,
    pub GetSourcePathElement: usize,
    pub SetSourcePath: usize,
    pub AppendSourcePath: usize,
    pub FindSourceFile: usize,
    pub GetSourceFileLineOffsets: usize,
    pub GetModuleVersionInformation: usize,
    pub GetModuleNameString: usize,
    pub GetConstantName: usize,
    pub GetFieldName: usize,
    pub GetTypeOptions: usize,
    pub AddTypeOptions: usize,
    pub RemoveTypeOptions: usize,
    pub SetTypeOptions: usize,
    pub GetNameByOffsetWide: usize,
    pub GetOffsetByNameWide: usize,
    pub GetNearNameByOffsetWide: usize,
    pub GetLineByOffsetWide: usize,
    pub GetOffsetByLineWide: usize,
    pub GetModuleByModuleNameWide: extern "system" fn(&DbgSyms, Name: PCWSTR, StartIndex: ULONG, Index: PULONG, Base: *mut u64) -> HRESULT,
    pub GetSymbolModuleWide: usize,
    pub GetTypeNameWide: usize,
    pub GetTypeIdWide: usize,
    pub GetFieldOffsetWide: usize,
    pub GetSymbolTypeIdWide: usize,
    pub GetScopeSymbolGroup2: usize,
    pub CreateSymbolGroup2: usize,
    pub StartSymbolMatchWide: extern "system" fn(&DbgSyms, PWSTR: *const u16, &mut u64) -> HRESULT,
    pub GetNextSymbolMatchWide: extern "system" fn(&DbgSyms, handle: u64, *mut u16, len: u32, match_size: Option<&mut u32>, Offset: Option<&mut u64>) -> HRESULT,
    pub ReloadWide: usize,
    pub GetSymbolPathWide: usize,
    pub SetSymbolPathWide: usize,
    pub AppendSymbolPathWide: usize,
    pub GetImagePathWide: extern "system" fn(&DbgSyms, PWSTR: *mut u16, BufferSize: u32, PathSize: &mut u32),
    pub SetImagePathWide: usize,
    pub AppendImagePathWide: usize,
    pub GetSourcePathWide: usize,
    pub GetSourcePathElementWide: usize,
    pub SetSourcePathWide: usize,
    pub AppendSourcePathWide: usize,
    pub FindSourceFileWide: usize,
    pub GetSourceFileLineOffsetsWide: usize,
    pub GetModuleVersionInformationWide: usize,
    pub GetModuleNameStringWide: extern "system" fn(&DbgSyms, Which: ULONG, Index: ULONG, Base: u64, Buffer: PWSTR, BufferSize: ULONG, NameSize: PULONG) -> HRESULT,
    pub GetConstantNameWide: usize,
    pub GetFieldNameWide: usize,
    pub IsManagedModule: usize,
    pub GetModuleByModuleName2: usize,
    pub GetModuleByModuleName2Wide: usize,
    pub GetModuleByOffset2: usize,
    pub AddSyntheticModule: usize,
    pub AddSyntheticModuleWide: usize,
    pub RemoveSyntheticModule: usize,
    pub GetCurrentScopeFrameIndex: usize,
    pub SetScopeFrameByIndex: usize,
    pub SetScopeFromJitDebugInfo: usize,
    pub SetScopeFromStoredEvent: usize,
    pub OutputSymbolByOffset: usize,
    pub GetFunctionEntryByOffset: usize,
    pub GetFieldTypeAndOffset: usize,
    pub GetFieldTypeAndOffsetWide: usize,
    pub AddSyntheticSymbol: usize,
    pub AddSyntheticSymbolWide: usize,
    pub RemoveSyntheticSymbol: usize,
    pub GetSymbolEntriesByOffset: usize,
    pub GetSymbolEntriesByName: usize,
    pub GetSymbolEntriesByNameWide: usize,
    pub GetSymbolEntryByToken: usize,
    pub GetSymbolEntryInformation: usize,
    pub GetSymbolEntryString: usize,
    pub GetSymbolEntryStringWide: usize,
    pub GetSymbolEntryOffsetRegions: usize,
    pub GetSymbolEntryBySymbolEntry: usize,
    pub GetSourceEntriesByOffset: usize,
    pub GetSourceEntriesByLine: usize,
    pub GetSourceEntriesByLineWide: usize,
    pub GetSourceEntryString: usize,
    pub GetSourceEntryStringWide: usize,
    pub GetSourceEntryOffsetRegions: usize,
    pub GetSourceEntryBySourceEntry: usize,
}

pub const DEBUG_BREAKPOINT_CODE: u32 = 0;
pub const DEBUG_BREAKPOINT_DATA: u32 = 1;
pub const DEBUG_BREAKPOINT_TIME: u32 = 2;
pub const DEBUG_BREAKPOINT_INLINE: u32 = 3;

pub const DEBUG_BREAKPOINT_GO_ONLY: u32    = 0x00000001;
pub const DEBUG_BREAKPOINT_DEFERRED: u32   = 0x00000002;
pub const DEBUG_BREAKPOINT_ENABLED: u32    = 0x00000004;
pub const DEBUG_BREAKPOINT_ADDER_ONLY: u32 = 0x00000008;
pub const DEBUG_BREAKPOINT_ONE_SHOT: u32   = 0x00000010;

// Data breakpoint access types.
// Different architectures support different
// sets of these bits.
pub const DEBUG_BREAK_READ: u32    = 0x00000001;
pub const DEBUG_BREAK_WRITE: u32   = 0x00000002;
pub const DEBUG_BREAK_EXECUTE: u32 = 0x00000004;
pub const DEBUG_BREAK_IO: u32      = 0x00000008;

#[repr(C)]
pub struct IDebugControl4_VTable {
    pub base: IUnknown,
    pub GetInterrupt: usize,
    pub SetInterrupt: extern "system" fn(&DbgControl, Flags: u32),
    pub GetInterruptTimeout: usize,
    pub SetInterruptTimeout: usize,
    pub GetLogFile: usize,
    pub OpenLogFile: usize,
    pub CloseLogFile: usize,
    pub GetLogMask: usize,
    pub SetLogMask: usize,
    pub Input: usize,
    pub ReturnInput: usize,
    pub Output: usize,
    pub OutputVaList: usize,
    pub ControlledOutput: usize,
    pub ControlledOutputVaList: usize,
    pub OutputPrompt: usize,
    pub OutputPromptVaList: usize,
    pub GetPromptText: usize,
    pub OutputCurrentState: usize,
    pub OutputVersionInformation: usize,
    pub GetNotifyEventHandle: usize,
    pub SetNotifyEventHandle: usize,
    pub Assemble: usize,
    pub Disassemble: usize,
    pub GetDisassembleEffectiveOffset: usize,
    pub OutputDisassembly: usize,
    pub OutputDisassemblyLines: usize,
    pub GetNearInstruction: usize,
    pub GetStackTrace: usize,
    pub GetReturnOffset: usize,
    pub OutputStackTrace: usize,
    pub GetDebuggeeType: usize,
    pub GetActualProcessorType: usize,
    pub GetExecutingProcessorType: usize,
    pub GetNumberPossibleExecutingProcessorTypes: usize,
    pub GetPossibleExecutingProcessorTypes: usize,
    pub GetNumberProcessors: usize,
    pub GetSystemVersion: usize,
    pub GetPageSize: usize,
    pub IsPointer64Bit: usize,
    pub ReadBugCheckData: usize,
    pub GetNumberSupportedProcessorTypes: usize,
    pub GetSupportedProcessorTypes: usize,
    pub GetProcessorTypeNames: usize,
    pub GetEffectiveProcessorType: usize,
    pub SetEffectiveProcessorType: usize,
    pub GetExecutionStatus: extern "system" fn(&DbgControl, _: &mut u32) -> HRESULT,
    pub SetExecutionStatus: extern "system" fn(&DbgControl, Flags: u32) -> HRESULT,
    pub GetCodeLevel: usize,
    pub SetCodeLevel: usize,
    pub GetEngineOptions: usize,
    pub AddEngineOptions: usize,
    pub RemoveEngineOptions: usize,
    pub SetEngineOptions: usize,
    pub GetSystemErrorControl: usize,
    pub SetSystemErrorControl: usize,
    pub GetTextMacro: usize,
    pub SetTextMacro: usize,
    pub GetRadix: usize,
    pub SetRadix: usize,
    pub Evaluate: usize,
    pub CoerceValue: usize,
    pub CoerceValues: usize,
    pub Execute: usize,
    pub ExecuteCommandFile: usize,
    pub GetNumberBreakpoints: usize,
    pub GetBreakpointByIndex: extern "system" fn(&DbgControl, Index: ULONG, bp: *mut *mut IDbgBp) -> HRESULT,
    pub GetBreakpointById: extern "system" fn(&DbgControl, Id: ULONG, bp: *mut *mut IDbgBp) -> HRESULT,
    pub GetBreakpointParameters: usize,
    pub AddBreakpoint: extern "system" fn(&DbgControl, Type: ULONG, DesiredId: ULONG, bp: *mut *mut IDbgBp) -> HRESULT,
    pub RemoveBreakpoint: extern "system" fn(&DbgControl, bp: *const IDbgBp) -> HRESULT,
    pub AddExtension: usize,
    pub RemoveExtension: usize,
    pub GetExtensionByPath: usize,
    pub CallExtension: usize,
    pub GetExtensionFunction: usize,
    pub GetWindbgExtensionApis32: usize,
    pub GetWindbgExtensionApis64: usize,
    pub GetNumberEventFilters: usize,
    pub GetEventFilterText: usize,
    pub GetEventFilterCommand: usize,
    pub SetEventFilterCommand: usize,
    pub GetSpecificFilterParameters: usize,
    pub SetSpecificFilterParameters: usize,
    pub GetSpecificFilterArgument: usize,
    pub SetSpecificFilterArgument: usize,
    pub GetExceptionFilterParameters: usize,
    pub SetExceptionFilterParameters: usize,
    pub GetExceptionFilterSecondCommand: usize,
    pub SetExceptionFilterSecondCommand: usize,
    pub WaitForEvent: extern "system" fn(&DbgControl, Flags: u32, Timeout: isize) -> HRESULT,
    pub GetLastEventInformation: usize,
    pub GetCurrentTimeDate: usize,
    pub GetCurrentSystemUpTime: usize,
    pub GetDumpFormatFlags: usize,
    pub GetNumberTextReplacements: usize,
    pub GetTextReplacement: usize,
    pub SetTextReplacement: usize,
    pub RemoveTextReplacements: usize,
    pub OutputTextReplacements: usize,
    pub GetAssemblyOptions: usize,
    pub AddAssemblyOptions: usize,
    pub RemoveAssemblyOptions: usize,
    pub SetAssemblyOptions: usize,
    pub GetExpressionSyntax: usize,
    pub SetExpressionSyntax: usize,
    pub SetExpressionSyntaxByName: usize,
    pub GetNumberExpressionSyntaxes: usize,
    pub GetExpressionSyntaxNames: usize,
    pub GetNumberEvents: usize,
    pub GetEventIndexDescription: usize,
    pub GetCurrentEventIndex: usize,
    pub SetNextEventIndex: usize,
    pub GetLogFileWide: usize,
    pub OpenLogFileWide: usize,
    pub InputWide: usize,
    pub ReturnInputWide: usize,
    pub OutputWide: usize,
    pub OutputVaListWide: usize,
    pub ControlledOutputWide: usize,
    pub ControlledOutputVaListWide: usize,
    pub OutputPromptWide: usize,
    pub OutputPromptVaListWide: usize,
    pub GetPromptTextWide: usize,
    pub AssembleWide: usize,
    pub DisassembleWide: usize,
    pub GetProcessorTypeNamesWide: usize,
    pub GetTextMacroWide: usize,
    pub SetTextMacroWide: usize,
    pub EvaluateWide: usize,
    pub ExecuteWide: extern "system" fn(&DbgControl, OutputControl: u32, Command: *const u16, Flags: u32) -> HRESULT,
    pub ExecuteCommandFileWide: usize,
    pub GetBreakpointByIndex2: usize,
    pub GetBreakpointById2: usize,
    pub AddBreakpoint2: usize,
    pub RemoveBreakpoint2: usize,
    pub AddExtensionWide: usize,
    pub GetExtensionByPathWide: usize,
    pub CallExtensionWide: usize,
    pub GetExtensionFunctionWide: usize,
    pub GetEventFilterTextWide: usize,
    pub GetEventFilterCommandWide: usize,
    pub SetEventFilterCommandWide: usize,
    pub GetSpecificFilterArgumentWide: usize,
    pub SetSpecificFilterArgumentWide: usize,
    pub GetExceptionFilterSecondCommandWide: usize,
    pub SetExceptionFilterSecondCommandWide: usize,
    pub GetLastEventInformationWide: usize,
    pub GetTextReplacementWide: usize,
    pub SetTextReplacementWide: usize,
    pub SetExpressionSyntaxByNameWide: usize,
    pub GetExpressionSyntaxNamesWide: usize,
    pub GetEventIndexDescriptionWide: usize,
    pub GetLogFile2: usize,
    pub OpenLogFile2: usize,
    pub GetLogFile2Wide: usize,
    pub OpenLogFile2Wide: usize,
    pub GetSystemVersionValues: usize,
    pub GetSystemVersionString: usize,
    pub GetSystemVersionStringWide: extern "system" fn(&DbgControl, which: u32, buf: *mut u16, size: usize, Option<&mut u32>),
    pub GetContextStackTrace: usize,
    pub OutputContextStackTrace: usize,
    pub GetStoredEventInformation: usize,
    pub GetManagedStatus: usize,
    pub GetManagedStatusWide: usize,
    pub ResetManagedStatus: usize,
}

#[repr(C)]
pub struct IDebugClient5_VTable {
    pub base: IUnknown,
    pub AttachKernel: usize,
    pub GetKernelConnectionOptions: usize,
    pub SetKernelConnectionOptions: usize,
    pub StartProcessServer: usize,
    pub ConnectProcessServer: usize,
    pub DisconnectProcessServer: usize,
    pub GetRunningProcessSystemIds: usize,
    pub GetRunningProcessSystemIdByExecutableName: usize,
    pub GetRunningProcessDescription: usize,
    pub AttachProcess: usize,
    pub CreateProcess: usize,
    pub CreateProcessAndAttach: usize,
    pub GetProcessOptions: usize,
    pub AddProcessOptions: usize,
    pub RemoveProcessOptions: usize,
    pub SetProcessOptions: usize,
    pub OpenDumpFile: usize,
    pub WriteDumpFile: usize,
    pub ConnectSession: usize,
    pub StartServer: usize,
    pub OutputServers: usize,
    pub TerminateProcesses: usize,
    pub DetachProcesses: usize,
    pub EndSession: extern "system" fn(&DbgClient, Flags: ULONG) -> HRESULT,
    pub GetExitCode: usize,
    pub DispatchCallbacks: usize,
    pub ExitDispatch: usize,
    pub CreateClient: usize,
    pub GetInputCallbacks: usize,
    pub SetInputCallbacks: usize,
    pub GetOutputCallbacks: usize,
    pub SetOutputCallbacks: usize,
    pub GetOutputMask: usize,
    pub SetOutputMask: usize,
    pub GetOtherOutputMask: usize,
    pub SetOtherOutputMask: usize,
    pub GetOutputWidth: usize,
    pub SetOutputWidth: usize,
    pub GetOutputLinePrefix: usize,
    pub SetOutputLinePrefix: usize,
    pub GetIdentity: usize,
    pub OutputIdentity: usize,
    pub GetEventCallbacks: usize,
    pub SetEventCallbacks: usize,
    pub FlushCallbacks: usize,
    pub WriteDumpFile2: usize,
    pub AddDumpInformationFile: usize,
    pub EndProcessServer: usize,
    pub WaitForProcessServerEnd: usize,
    pub IsKernelDebuggerEnabled: usize,
    pub TerminateCurrentProcess: extern "system" fn(&DbgClient) -> HRESULT,
    pub DetachCurrentProcess: extern "system" fn(&DbgClient) -> HRESULT,
    pub AbandonCurrentProcess: usize,
    pub GetRunningProcessSystemIdByExecutableNameWide: usize,
    pub GetRunningProcessDescriptionWide: usize,
    pub CreateProcessWide: extern "system" fn(&DbgClient, Server: u64, CommandLine: PCWSTR, CreateFlags: ULONG) -> HRESULT,
    pub CreateProcessAndAttachWide: usize,
    pub OpenDumpFileWide: extern "system" fn(&DbgClient, Options: PCWSTR, Flags: PVOID) -> HRESULT,
    pub WriteDumpFileWide: usize,
    pub AddDumpInformationFileWide: usize,
    pub GetNumberDumpFiles: usize,
    pub GetDumpFile: usize,
    pub GetDumpFileWide: usize,
    pub AttachKernelWide: extern "system" fn(&DbgClient, Flags: ULONG, Options: PCWSTR) -> HRESULT,
    pub GetKernelConnectionOptionsWide: usize,
    pub SetKernelConnectionOptionsWide: usize,
    pub StartProcessServerWide: usize,
    pub ConnectProcessServerWide: usize,
    pub StartServerWide: usize,
    pub OutputServersWide: usize,
    pub GetOutputCallbacksWide: usize,
    pub SetOutputCallbacksWide: usize,
    pub GetOutputLinePrefixWide: usize,
    pub SetOutputLinePrefixWide: usize,
    pub GetIdentityWide: usize,
    pub OutputIdentityWide: usize,
    pub GetEventCallbacksWide: usize,
    pub SetEventCallbacksWide: usize,
    pub CreateProcess2: usize,
    pub CreateProcess2Wide: usize,
    pub CreateProcessAndAttach2: usize,
    pub CreateProcessAndAttach2Wide: usize,
    pub PushOutputLinePrefix: usize,
    pub PushOutputLinePrefixWide: usize,
    pub PopOutputLinePrefix: usize,
    pub GetNumberInputCallbacks: usize,
    pub GetNumberOutputCallbacks: usize,
    pub GetNumberEventCallbacks: usize,
    pub GetQuitLockString: usize,
    pub SetQuitLockString: usize,
    pub GetQuitLockStringWide: usize,
    pub SetQuitLockStringWide: usize,
}

pub struct IDebugSystemObjects4_VTable {
    pub base: IUnknown,
    pub GetEventThread: usize,
    pub GetEventProcess: usize,
    pub GetCurrentThreadId: extern "system" fn(&DbgSysobj, tid: &mut u32),
    pub SetCurrentThreadId: usize,
    pub GetCurrentProcessId: usize,
    pub SetCurrentProcessId: usize,
    pub GetNumberThreads: extern "system" fn(&DbgSysobj, count: &mut u32),
    pub GetTotalNumberThreads: usize,
    pub GetThreadIdsByIndex: extern "system" fn(&DbgSysobj, start: u32, count: u32, ids: *mut u32, sysids: *mut u32),
    pub GetThreadIdByProcessor: usize,
    pub GetCurrentThreadDataOffset: usize,
    pub GetThreadIdByDataOffset: usize,
    pub GetCurrentThreadTeb: usize,
    pub GetThreadIdByTeb: usize,
    pub GetCurrentThreadSystemId: extern "system" fn(&DbgSysobj, tid: &mut u32),
    pub GetThreadIdBySystemId: usize,
    pub GetCurrentThreadHandle: usize,
    pub GetThreadIdByHandle: usize,
    pub GetNumberProcesses: extern "system" fn(&DbgSysobj, count: &mut u32),
    pub GetProcessIdsByIndex: usize,
    pub GetCurrentProcessDataOffset: usize,
    pub GetProcessIdByDataOffset: usize,
    pub GetCurrentProcessPeb: extern "system" fn(&DbgSysobj, Flags: &mut u64),
    pub GetProcessIdByPeb: usize,
    pub GetCurrentProcessSystemId: extern "system" fn(&DbgSysobj, pid: &mut u32),
    pub GetProcessIdBySystemId: usize,
    pub GetCurrentProcessHandle: extern "system" fn(&DbgSysobj, _: &mut u64),
    pub GetProcessIdByHandle: usize,
    pub GetCurrentProcessExecutableName: usize,
    pub GetCurrentProcessUpTime: usize,
    pub GetImplicitThreadDataOffset: usize,
    pub SetImplicitThreadDataOffset: usize,
    pub GetImplicitProcessDataOffset: usize,
    pub SetImplicitProcessDataOffset: usize,
    pub GetEventSystem: usize,
    pub GetCurrentSystemId: usize,
    pub SetCurrentSystemId: usize,
    pub GetNumberSystems: extern "system" fn(&DbgSysobj, count: &mut u32),
    pub GetSystemIdsByIndex: usize,
    pub GetTotalNumberThreadsAndProcesses: usize,
    pub GetCurrentSystemServer: usize,
    pub GetSystemByServer: usize,
    pub GetCurrentSystemServerName: usize,
    pub GetCurrentProcessExecutableNameWide: extern "system" fn(&DbgSysobj, PWSTR: *mut u16, BufferSize: u32, PathSize: &mut u32),
    pub GetCurrentSystemServerNameWide: usize,
}

#[repr(C)]
pub struct IDebugBreakpoint_VTable {
    pub base: IUnknown,
    pub GetId: extern "system" fn(&IDbgBp, *mut u32) -> HRESULT,
    pub GetType: extern "system" fn(&IDbgBp, *mut u32, *mut u32) -> HRESULT,
    pub GetAdder: usize,
    pub GetFlags: extern "system" fn(&IDbgBp, *mut u32) -> HRESULT,
    pub AddFlags: extern "system" fn(&IDbgBp, u32) -> HRESULT,
    pub RemoveFlags: extern "system" fn(&IDbgBp, u32) -> HRESULT,
    pub SetFlags: extern "system" fn(&IDbgBp, u32) -> HRESULT,
    pub GetOffset: extern "system" fn(&IDbgBp, *mut u64) -> HRESULT,
    pub SetOffset: extern "system" fn(&IDbgBp, u64),
    pub GetDataParameters: usize,
    pub SetDataParameters: extern "system" fn(&IDbgBp, u32, u32) -> HRESULT,
    pub GetPassCount: extern "system" fn(&IDbgBp, *mut u32) -> HRESULT,
    pub SetPassCount: extern "system" fn(&IDbgBp, u32) -> HRESULT,
    pub GetCurrentPassCount: usize,
    pub GetMatchThreadId: extern "system" fn(&IDbgBp, *mut u32) -> HRESULT,
    pub SetMatchThreadId: extern "system" fn(&IDbgBp, u32) -> HRESULT,
    pub GetCommand: usize,
    pub SetCommand: usize,
    pub GetOffsetExpression: usize,
    pub SetOffsetExpression: usize,
    pub GetParameters: usize,
}

#[repr(C)]
pub struct IDebugDataSpaces4_VTable {
    pub base: IUnknown,
    pub ReadVirtual: extern "C" fn(&DbgSpaces, Offset: u64, Buffer: *mut u8, BufferSize: ULONG, BytesRead: PULONG) -> HRESULT,
    pub WriteVirtual: extern "C" fn(&DbgSpaces, Offset: u64, Buffer: *const u8, BufferSize: ULONG, BytesWritten: PULONG) -> HRESULT,
    pub SearchVirtual: usize,
    pub ReadVirtualUncached: usize,
    pub WriteVirtualUncached: usize,
    pub ReadPointersVirtual: usize,
    pub WritePointersVirtual: usize,
    pub ReadPhysical: usize,
    pub WritePhysical: usize,
    pub ReadControl: usize,
    pub WriteControl: usize,
    pub ReadIo: usize,
    pub WriteIo: usize,
    pub ReadMsr: usize,
    pub WriteMsr: usize,
    pub ReadBusData: usize,
    pub WriteBusData: usize,
    pub CheckLowMemory: usize,
    pub ReadDebuggerData: usize,
    pub ReadProcessorSystemData: usize,
    pub VirtualToPhysical: usize,
    pub GetVirtualTranslationPhysicalOffsets: usize,
    pub ReadHandleData: usize,
    pub FillVirtual: usize,
    pub FillPhysical: usize,
    pub QueryVirtual: usize,
    pub ReadImageNtHeaders: extern "C" fn(&DbgSpaces, base: u64, PIMAGE_NT_HEADERS64),
    pub ReadTagged: usize,
    pub StartEnumTagged: usize,
    pub GetNextTagged: usize,
    pub EndEnumTagged: usize,
    pub GetOffsetInformation: extern "C" fn(&DbgSpaces, Space: ULONG, Which: ULONG, Offset: u64, Buffer: PVOID, BufferSize: ULONG, InfoSize: PULONG) -> HRESULT,
    pub GetNextDifferentlyValidOffsetVirtual: usize,
    pub GetValidRegionVirtual: usize,
    pub SearchVirtual2: usize,
    pub ReadMultiByteStringVirtual: usize,
    pub ReadMultiByteStringVirtualWide: usize,
    pub ReadUnicodeStringVirtual: usize,
    pub ReadUnicodeStringVirtualWide: usize,
    pub ReadPhysical2: usize,
    pub WritePhysical2: usize,
}

#[derive(Deref, Copy, Clone)]
pub struct IDbgBp(&'static IDebugBreakpoint_VTable);

#[derive(Deref)]
pub struct DbgClient(&'static IDebugClient5_VTable);

#[derive(Deref)]
pub struct DbgControl(&'static IDebugControl4_VTable);

#[derive(Deref)]
pub struct DbgSpaces(&'static IDebugDataSpaces4_VTable);

#[repr(C)]
pub struct DbgRegs;

#[repr(C)]
#[derive(Deref)]
pub struct DbgSyms(&'static IDebugSymbols3_VTable);

#[repr(C)]
#[derive(Deref)]
pub struct DbgSysobj(&'static IDebugSystemObjects4_VTable);

#[repr(C)]
pub struct DbgAdv;