using System.Net;
using System.Runtime.InteropServices;
using NTShield.Shared.Enums;

namespace NTShield.Collectors.Windows.Native;

/// <summary>
/// P/Invoke for IP Helper APIs available since Windows Server 2012 (and earlier).
/// GetExtendedTcpTable / GetExtendedUdpTable — preferred over netstat polling.
/// </summary>
internal static class IpHelperNative
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int ErrorInsufficientBuffer = 122;

    private enum TcpTableClass
    {
        TcpTableOwnerPidAll = 5
    }

    private enum UdpTableClass
    {
        UdpTableOwnerPid = 1
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdpRowOwnerPid
    {
        public uint LocalAddr;
        public uint LocalPort;
        public uint OwningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int dwOutBufLen,
        bool sort,
        int ipVersion,
        TcpTableClass tblClass,
        uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable,
        ref int dwOutBufLen,
        bool sort,
        int ipVersion,
        UdpTableClass tblClass,
        uint reserved);

    public sealed record TcpRow(
        string LocalAddress,
        int LocalPort,
        string RemoteAddress,
        int RemotePort,
        TcpConnectionState State,
        int ProcessId);

    public sealed record UdpRow(
        string LocalAddress,
        int LocalPort,
        int ProcessId);

    public static IReadOnlyList<TcpRow> GetTcpConnections()
    {
        var list = new List<TcpRow>();
        list.AddRange(GetTcpTable(AfInet));
        // IPv6 optional; Server 2012 supports it. Failures are ignored.
        try { list.AddRange(GetTcpTable(AfInet6)); } catch { /* ignore */ }
        return list;
    }

    public static IReadOnlyList<UdpRow> GetUdpListeners()
    {
        var list = new List<UdpRow>();
        list.AddRange(GetUdpTable(AfInet));
        try { list.AddRange(GetUdpTable(AfInet6)); } catch { /* ignore */ }
        return list;
    }

    private static List<TcpRow> GetTcpTable(int addressFamily)
    {
        var result = new List<TcpRow>();
        int bufferSize = 0;
        var ret = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, addressFamily, TcpTableClass.TcpTableOwnerPidAll, 0);
        if (ret != 0 && ret != ErrorInsufficientBuffer)
        {
            throw new InvalidOperationException($"GetExtendedTcpTable size query failed: {ret}");
        }

        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            ret = GetExtendedTcpTable(buffer, ref bufferSize, true, addressFamily, TcpTableClass.TcpTableOwnerPidAll, 0);
            if (ret != 0)
            {
                throw new InvalidOperationException($"GetExtendedTcpTable failed: {ret}");
            }

            var numEntries = Marshal.ReadInt32(buffer);
            var rowPtr = IntPtr.Add(buffer, 4);
            var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();

            // Note: IPv6 extended table uses different row layout. For Server 2012 safety we only parse IPv4 fully here.
            if (addressFamily != AfInet)
            {
                return result;
            }

            for (var i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(IntPtr.Add(rowPtr, i * rowSize));
                result.Add(new TcpRow(
                    ConvertIpv4(row.LocalAddr),
                    ConvertPort(row.LocalPort),
                    ConvertIpv4(row.RemoteAddr),
                    ConvertPort(row.RemotePort),
                    (TcpConnectionState)row.State,
                    (int)row.OwningPid));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return result;
    }

    private static List<UdpRow> GetUdpTable(int addressFamily)
    {
        var result = new List<UdpRow>();
        int bufferSize = 0;
        var ret = GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true, addressFamily, UdpTableClass.UdpTableOwnerPid, 0);
        if (ret != 0 && ret != ErrorInsufficientBuffer)
        {
            throw new InvalidOperationException($"GetExtendedUdpTable size query failed: {ret}");
        }

        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            ret = GetExtendedUdpTable(buffer, ref bufferSize, true, addressFamily, UdpTableClass.UdpTableOwnerPid, 0);
            if (ret != 0)
            {
                throw new InvalidOperationException($"GetExtendedUdpTable failed: {ret}");
            }

            if (addressFamily != AfInet)
            {
                return result;
            }

            var numEntries = Marshal.ReadInt32(buffer);
            var rowPtr = IntPtr.Add(buffer, 4);
            var rowSize = Marshal.SizeOf<MibUdpRowOwnerPid>();
            for (var i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MibUdpRowOwnerPid>(IntPtr.Add(rowPtr, i * rowSize));
                result.Add(new UdpRow(
                    ConvertIpv4(row.LocalAddr),
                    ConvertPort(row.LocalPort),
                    (int)row.OwningPid));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return result;
    }

    private static string ConvertIpv4(uint addr) =>
        new IPAddress(BitConverter.GetBytes(addr)).ToString();

    private static int ConvertPort(uint port) =>
        (int)(((port & 0xFF) << 8) | ((port >> 8) & 0xFF));
}
