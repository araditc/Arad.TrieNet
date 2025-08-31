using System.Collections.Concurrent;
using System.Net;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Text;

namespace Arad.TrieNet;

/// <summary>
///     Provides ultra-fast, thread-safe IP filtering using a Trie-based data structure.
/// </summary>
/// <remarks>
///     Optimized for high-performance scenarios (100,000+ RPS, 200,000 users) with minimal memory usage (&lt;50MB for 1M
///     CIDRs).
///     Supports IPv4/IPv6 CIDR-based networks and a bucket-based deny list.
/// </remarks>
public static class IPFilter
{
    private const int IPv4Stride = 8;
    private const int IPv6Stride = 16;

    private static readonly Node?[] _roots4 = new Node?[256];
    private static readonly ConcurrentDictionary<int, Node> _roots6 = new();
    private static readonly ConcurrentDictionary<string, (bool IPv4AllAllowed, bool IPv6AllAllowed)> _userAllAllowed = new();
    private static readonly ConcurrentDictionary<string, string> _cidrToUser = new();
    private static readonly ConcurrentDictionary<string, ConcurrentHashSet<string>> _userToCidrsIndex = new();
    private static readonly ConcurrentHashSet<DenyEntry> _globalDenyList = new();
    private static readonly ConcurrentDictionary<int, ConcurrentHashSet<DenyEntry>> _denyListIPv4Buckets = new();
    private static readonly ConcurrentDictionary<int, ConcurrentHashSet<DenyEntry>> _denyListIPv6Buckets = new();
    private static readonly ReaderWriterLockSlim _lock = new();
    private static string? _v4AllOwner;
    private static string? _v6AllOwner;

    /// <summary>
    ///     Adds a network or range to a user's allowed list.
    /// </summary>
    /// <param name="cidrOrRange">The CIDR or IP range (e.g., "192.168.1.0/24" or "192.168.1.1-192.168.1.10"). </param>
    /// <param name="username">The user ID to associate with the network.</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void AddNetwork(ReadOnlySpan<char> cidrOrRange, string username)
    {
        (string Ip, int Prefix)[] cidrs = ParseCidrOrRange(cidrOrRange, out bool isIPv6);
        if (cidrs.Length == 0)
        {
            return;
        }

        _lock.EnterWriteLock();
        try
        {
            Span<byte> ipBytes = stackalloc byte[isIPv6 ? 16 : 4];
            foreach ((string ip, int prefix) in cidrs)
            {
                if (!TryParseIp(ip.AsSpan(), ipBytes, isIPv6))
                {
                    continue;
                }

                if (prefix == 0)
                {
                    (bool ipv4, bool ipv6) = _userAllAllowed.GetOrAdd(username, _ => (false, false));
                    string key = isIPv6 ? "::/0" : "0.0.0.0/0";

                    if (_cidrToUser.TryGetValue(key, out string? value) && value != username)
                    {
                        if (_userToCidrsIndex.TryGetValue(value, out ConcurrentHashSet<string>? prevSet))
                        {
                            prevSet.TryRemove(key);
                        }

                        if (_userAllAllowed.TryGetValue(value, out (bool IPv4AllAllowed, bool IPv6AllAllowed) prevFlags))
                        {
                            if (isIPv6)
                            {
                                prevFlags.IPv6AllAllowed = false;
                            }
                            else
                            {
                                prevFlags.IPv4AllAllowed = false;
                            }

                            _userAllAllowed[value] = prevFlags;
                        }
                    }

                    if (isIPv6)
                    {
                        ipv6 = true;
                        _v6AllOwner = username;
                    }
                    else
                    {
                        ipv4 = true;
                        _v4AllOwner = username;
                    }

                    _userAllAllowed[username] = (ipv4, ipv6);

                    _cidrToUser[key] = username;
                    ConcurrentHashSet<string> userCidrsList = _userToCidrsIndex.GetOrAdd(username, _ => new());
                    userCidrsList.Add(key);
                    continue;
                }

                ApplyNetmask(ipBytes, prefix);
                string cidrString = ToCidrString(ipBytes, prefix, isIPv6);

                if (_cidrToUser.TryGetValue(cidrString, out string? prevUser) && prevUser != username)
                {
                    if (_userToCidrsIndex.TryGetValue(prevUser, out ConcurrentHashSet<string>? prevSet))
                    {
                        prevSet.TryRemove(cidrString);
                    }
                }

                if (isIPv6)
                {
                    InsertIPv6Network(ipBytes, prefix, cidrString, username);
                }
                else
                {
                    InsertIPv4Network(ipBytes, prefix, cidrString, username);
                }

                _cidrToUser[cidrString] = username;
                ConcurrentHashSet<string> userCidrs = _userToCidrsIndex.GetOrAdd(username, _ => new());
                userCidrs.Add(cidrString);
            }
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    /// <summary>
    ///     Adds a network or range to the global deny list.
    /// </summary>
    /// <param name="cidrOrRange">The CIDR or IP range to deny.</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void AddDeny(ReadOnlySpan<char> cidrOrRange)
    {
        (string Ip, int Prefix)[] cidrs = ParseCidrOrRange(cidrOrRange, out bool isIPv6);
        if (cidrs.Length == 0)
        {
            return;
        }

        _lock.EnterWriteLock();
        try
        {
            Span<byte> ipBytes = stackalloc byte[isIPv6 ? 16 : 4];
            foreach ((string ip, int prefix) in cidrs)
            {
                if (!TryParseIp(ip.AsSpan(), ipBytes, isIPv6))
                {
                    continue;
                }

                ApplyNetmask(ipBytes, prefix);
                byte[] net = ipBytes.ToArray();
                DenyEntry entry = new(isIPv6, net, prefix);
                int stride = isIPv6 ? IPv6Stride : IPv4Stride;
                int firstBucket = isIPv6 ? (ipBytes[0] << 8) | ipBytes[1] : ipBytes[0];
                if (prefix < stride)
                {
                    int span = 1 << (stride - prefix);
                    int start = (firstBucket >> (stride - prefix)) << (stride - prefix);
                    for (int b = start; b < start + span; b++)
                    {
                        ConcurrentDictionary<int, ConcurrentHashSet<DenyEntry>> dict = isIPv6 ? _denyListIPv6Buckets : _denyListIPv4Buckets;
                        ConcurrentHashSet<DenyEntry> set = dict.GetOrAdd(b, _ => new());
                        set.Add(entry);
                    }
                }
                else
                {
                    int bucket = firstBucket;
                    ConcurrentDictionary<int, ConcurrentHashSet<DenyEntry>> dict = isIPv6 ? _denyListIPv6Buckets : _denyListIPv4Buckets;
                    ConcurrentHashSet<DenyEntry> set = dict.GetOrAdd(bucket, _ => new());
                    set.Add(entry);
                }

                _globalDenyList.Add(entry);
            }
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    /// <summary>
    ///     Removes a network or range from a user's allowed list.
    /// </summary>
    /// <param name="cidrOrRange">The CIDR or IP range to remove. </param>
    /// <param name="username">The user ID associated with the network. </param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void RemoveNetwork(ReadOnlySpan<char> cidrOrRange, string username)
    {
        (string Ip, int Prefix)[] cidrs = ParseCidrOrRange(cidrOrRange, out bool isIPv6);
        if (cidrs.Length == 0)
        {
            return;
        }

        _lock.EnterWriteLock();
        try
        {
            Span<byte> ipBytes = stackalloc byte[isIPv6 ? 16 : 4];
            foreach ((string ip, int prefix) in cidrs)
            {
                if (!TryParseIp(ip.AsSpan(), ipBytes, isIPv6))
                {
                    continue;
                }

                if (prefix == 0)
                {
                    (bool ipv4, bool ipv6) = _userAllAllowed.GetOrAdd(username, _ => (false, false));
                    if (isIPv6 && _v6AllOwner == username)
                    {
                        ipv6 = false;
                        _v6AllOwner = null;
                    }
                    else if (!isIPv6 && _v4AllOwner == username)
                    {
                        ipv4 = false;
                        _v4AllOwner = null;
                    }

                    _userAllAllowed[username] = (ipv4, ipv6);

                    string key = isIPv6 ? "::/0" : "0.0.0.0/0";
                    if (_cidrToUser.TryGetValue(key, out string? value) && value == username)
                    {
                        _cidrToUser.TryRemove(key, out _);
                        if (_userToCidrsIndex.TryGetValue(username, out ConcurrentHashSet<string>? userCidrs))
                        {
                            userCidrs.TryRemove(key);
                        }
                    }

                    continue;
                }

                ApplyNetmask(ipBytes, prefix);
                string cidrString = ToCidrString(ipBytes, prefix, isIPv6);

                if (isIPv6)
                {
                    int first16 = (ipBytes[0] << 8) | ipBytes[1];
                    if (prefix < IPv6Stride)
                    {
                        int range = 1 << (IPv6Stride - prefix);
                        int startRoot = (first16 >> (IPv6Stride - prefix)) << (IPv6Stride - prefix);
                        for (int root = startRoot; root < startRoot + range; root++)
                        {
                            if (_roots6.TryGetValue(root, out Node? current) && current.UserId == username)
                            {
                                current.IsAllowed = false;
                                current.Cidr = null;
                                current.UserId = null;
                            }
                        }
                    }
                    else if (_roots6.TryGetValue(first16, out Node? current))
                    {
                        int bit = IPv6Stride;
                        while (bit < prefix)
                        {
                            int byteIndex = bit / 8;
                            int bitIndex = 7 - (bit % 8);
                            int bitValue = (ipBytes[byteIndex] >> bitIndex) & 1;
                            current = current?.Children[bitValue];

                            if (current != null)
                            {
                                bit = current.BitIndex + 1;
                            }
                        }

                        if (current?.UserId == username)
                        {
                            current.IsAllowed = false;
                            current.Cidr = null;
                            current.UserId = null;
                        }
                    }
                }
                else
                {
                    int first = ipBytes[0];
                    if (prefix < IPv4Stride)
                    {
                        int range = 1 << (IPv4Stride - prefix);
                        int startRoot = (first >> (IPv4Stride - prefix)) << (IPv4Stride - prefix);
                        for (int root = startRoot; root < startRoot + range; root++)
                        {
                            if (_roots4[root] != null)
                            {
                                Node current = _roots4[root]!;
                                if (current.UserId == username)
                                {
                                    current.IsAllowed = false;
                                    current.Cidr = null;
                                    current.UserId = null;
                                }
                            }
                        }
                    }
                    else if (_roots4[first] != null)
                    {
                        Node? current = _roots4[first]!;
                        int bit = IPv4Stride;

                        while (bit < prefix)
                        {
                            int byteIndex = bit / 8;
                            int bitIndex = 7 - (bit % 8);
                            int bitValue = (ipBytes[byteIndex] >> bitIndex) & 1;
                            current = current.Children[bitValue];

                            if (current != null)
                            {
                                bit = current.BitIndex + 1;
                            }
                            else
                            {
                                break;
                            }
                        }

                        if (current?.UserId == username)
                        {
                            current.IsAllowed = false;
                            current.Cidr = null;
                            current.UserId = null;
                        }
                    }
                }

                if (_cidrToUser.TryGetValue(cidrString, out string? storedUsername) && storedUsername == username)
                {
                    _cidrToUser.TryRemove(cidrString, out _);
                    if (_userToCidrsIndex.TryGetValue(username, out ConcurrentHashSet<string>? userCidrs))
                    {
                        userCidrs.TryRemove(cidrString);
                    }
                }
            }
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    /// <summary>
    ///     Removes a network or range from the global deny list.
    /// </summary>
    /// <param name="cidrOrRange">The CIDR or IP range to remove.</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void RemoveDeny(ReadOnlySpan<char> cidrOrRange)
    {
        (string Ip, int Prefix)[] cidrs = ParseCidrOrRange(cidrOrRange, out bool isIPv6);
        if (cidrs.Length == 0)
        {
            return;
        }

        _lock.EnterWriteLock();
        try
        {
            Span<byte> ipBytes = stackalloc byte[isIPv6 ? 16 : 4];
            foreach ((string ip, int prefix) in cidrs)
            {
                if (!TryParseIp(ip.AsSpan(), ipBytes, isIPv6))
                {
                    continue;
                }

                ApplyNetmask(ipBytes, prefix);
                byte[] net = ipBytes.ToArray();
                DenyEntry entry = new(isIPv6, net, prefix);
                int stride = isIPv6 ? IPv6Stride : IPv4Stride;
                int firstBucket = isIPv6 ? (ipBytes[0] << 8) | ipBytes[1] : ipBytes[0];
                if (prefix < stride)
                {
                    int span = 1 << (stride - prefix);
                    int start = (firstBucket >> (stride - prefix)) << (stride - prefix);
                    for (int b = start; b < start + span; b++)
                    {
                        ConcurrentDictionary<int, ConcurrentHashSet<DenyEntry>> dict = isIPv6 ? _denyListIPv6Buckets : _denyListIPv4Buckets;
                        if (dict.TryGetValue(b, out ConcurrentHashSet<DenyEntry>? set) && set.TryRemove(entry) && set.IsEmpty)
                        {
                            dict.TryRemove(b, out _);
                        }
                    }
                }
                else
                {
                    ConcurrentDictionary<int, ConcurrentHashSet<DenyEntry>> dict = isIPv6 ? _denyListIPv6Buckets : _denyListIPv4Buckets;
                    if (dict.TryGetValue(firstBucket, out ConcurrentHashSet<DenyEntry>? set) && set.TryRemove(entry) && set.IsEmpty)
                    {
                        dict.TryRemove(firstBucket, out _);
                    }
                }

                _globalDenyList.TryRemove(entry);
            }
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    /// <summary>
    ///     Checks if an IP address is allowed for a specific user.
    /// </summary>
    /// <param name="userName">The user ID to check. </param>
    /// <param name="xForwardedFor">The IP address or X-Forwarded-For header. </param>
    /// <returns>A tuple indicating if the IP is allowed and the reason.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static (bool IsAllowed, string Reason) IsAllowed(string userName, ReadOnlySpan<char> xForwardedFor)
    {
        if (string.IsNullOrEmpty(userName) || xForwardedFor.IsEmpty)
        {
            return (false, "invalid input");
        }

        ReadOnlySpan<char> ipSpan = ExtractIpSpan(xForwardedFor);
        if (ipSpan.IsEmpty)
        {
            return (false, "invalid IP");
        }

        bool isIPv6 = ipSpan.Contains(':');
        Span<byte> ipBytes = stackalloc byte[isIPv6 ? 16 : 4];
        if (!TryParseIp(ipSpan, ipBytes, isIPv6))
        {
            return (false, "invalid IP");
        }

        _lock.EnterReadLock();
        try
        {
            if (IsInDenyList(ipBytes, isIPv6))
            {
                return (false, "blacklisted");
            }

            if (_userAllAllowed.TryGetValue(userName, out (bool IPv4AllAllowed, bool IPv6AllAllowed) allowed) && (isIPv6 ? allowed.IPv6AllAllowed : allowed.IPv4AllAllowed))
            {
                return (true, "allowed");
            }

            Node? current;
            if (isIPv6)
            {
                if (!_roots6.TryGetValue((ipBytes[0] << 8) | ipBytes[1], out current))
                {
                    return (false, "not allowed");
                }
            }
            else
            {
                if (_roots4[ipBytes[0]] == null)
                {
                    return (false, "not allowed");
                }

                current = _roots4[ipBytes[0]];
            }

            if (current == null)
            {
                return (false, "not allowed");
            }

            bool isAllowed = false;
            int startBit = isIPv6 ? IPv6Stride : IPv4Stride;

            int bit = startBit;
            while (bit < ipBytes.Length * 8)
            {
                if (current.IsAllowed && current.UserId == userName)
                {
                    isAllowed = true;
                }

                int byteIndex = bit / 8;
                int bitIndex = 7 - (bit % 8);
                int bitValue = (ipBytes[byteIndex] >> bitIndex) & 1;
                current = current.Children[bitValue];

                if (current != null)
                {
                    bit = current.BitIndex + 1;
                }
                else
                {
                    break;
                }
            }

            if (current is { IsAllowed: true } && current.UserId == userName)
            {
                isAllowed = true;
            }

            return (isAllowed, isAllowed ? "allowed" : "not allowed");
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    /// <summary>
    ///     Finds the owner of an IP address.
    /// </summary>
    /// <param name="xForwardedFor">The IP address or X-Forwarded-For header. </param>
    /// <returns>A tuple containing the owner and the reason.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static (string? Username, string Reason) FindOwner(ReadOnlySpan<char> xForwardedFor)
    {
        if (xForwardedFor.IsEmpty)
        {
            return (null, "invalid input");
        }

        ReadOnlySpan<char> ipSpan = ExtractIpSpan(xForwardedFor);
        if (ipSpan.IsEmpty)
        {
            return (null, "invalid IP");
        }

        bool isIPv6 = ipSpan.Contains(':');
        Span<byte> ipBytes = stackalloc byte[isIPv6 ? 16 : 4];
        if (!TryParseIp(ipSpan, ipBytes, isIPv6))
        {
            return (null, "invalid IP");
        }

        _lock.EnterReadLock();
        try
        {
            if (IsInDenyList(ipBytes, isIPv6))
            {
                return (null, "blacklisted");
            }

            Node? current;
            string? matchedUserId = null;
            if (isIPv6)
            {
                if (!_roots6.TryGetValue((ipBytes[0] << 8) | ipBytes[1], out current))
                {
                    return _v6AllOwner is not null ? (_v6AllOwner, "allowed") : (null, "not found");
                }
            }
            else
            {
                if (_roots4[ipBytes[0]] == null)
                {
                    return _v4AllOwner is not null ? (_v4AllOwner, "allowed") : (null, "not found");
                }

                current = _roots4[ipBytes[0]];
            }

            int startBit = isIPv6 ? IPv6Stride : IPv4Stride;

            int bit = startBit;
            while (bit < ipBytes.Length * 8)
            {
                if (current!.IsAllowed && current.UserId != null)
                {
                    matchedUserId = current.UserId;
                }

                int byteIndex = bit / 8;
                int bitIndex = 7 - (bit % 8);
                int bitValue = (ipBytes[byteIndex] >> bitIndex) & 1;
                current = current.Children[bitValue];

                if (current != null)
                {
                    bit = current.BitIndex + 1;
                }
                else
                {
                    break;
                }
            }

            if (current is { IsAllowed: true, UserId: not null })
            {
                matchedUserId = current.UserId;
            }

            if (matchedUserId != null)
            {
                return (matchedUserId, "allowed");
            }

            return isIPv6 ? _v6AllOwner is not null ? (_v6AllOwner, "allowed") : (null, "not found")
                   : _v4AllOwner is not null ? (_v4AllOwner, "allowed") : (null, "not found");
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    /// <summary>
    ///     Finds the owner and CIDR of an IP address.
    /// </summary>
    /// <param name="xForwardedFor">The IP address or X-Forwarded-For header. </param>
    /// <returns>A tuple containing the owner, CIDR, and reason.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static (string? Username, string? Cidr, string Reason) FindOwnerWithCidr(ReadOnlySpan<char> xForwardedFor)
    {
        if (xForwardedFor.IsEmpty)
        {
            return (null, null, "invalid input");
        }

        ReadOnlySpan<char> ipSpan = ExtractIpSpan(xForwardedFor);
        if (ipSpan.IsEmpty)
        {
            return (null, null, "invalid IP");
        }

        bool isIPv6 = ipSpan.Contains(':');
        Span<byte> ipBytes = stackalloc byte[isIPv6 ? 16 : 4];
        if (!TryParseIp(ipSpan, ipBytes, isIPv6))
        {
            return (null, null, "invalid IP");
        }

        _lock.EnterReadLock();
        try
        {
            if (IsInDenyList(ipBytes, isIPv6))
            {
                return (null, null, "blacklisted");
            }

            Node? current;
            string? matchedUser = null, matchedCidr = null;
            if (isIPv6)
            {
                if (!_roots6.TryGetValue((ipBytes[0] << 8) | ipBytes[1], out current))
                {
                    return _v6AllOwner is not null ? (_v6AllOwner, "::/0", "allowed") : (null, null, "not found");
                }
            }
            else
            {
                if (_roots4[ipBytes[0]] == null)
                {
                    return _v4AllOwner is not null ? (_v4AllOwner, "0.0.0.0/0", "allowed") : (null, null, "not found");
                }

                current = _roots4[ipBytes[0]];
            }

            int startBit = isIPv6 ? IPv6Stride : IPv4Stride;
            int bit = startBit;

            while (bit < ipBytes.Length * 8)
            {
                if (current!.IsAllowed && current.UserId != null)
                {
                    matchedUser = current.UserId;
                    matchedCidr = current.Cidr;
                }

                int byteIndex = bit / 8;
                int bitIndex = 7 - (bit % 8);
                int bitValue = (ipBytes[byteIndex] >> bitIndex) & 1;
                current = current.Children[bitValue];

                if (current != null)
                {
                    bit = current.BitIndex + 1;
                }
                else
                {
                    break;
                }
            }

            if (current is { IsAllowed: true, UserId: not null })
            {
                matchedUser = current.UserId;
                matchedCidr = current.Cidr;
            }

            if (matchedUser != null)
            {
                return (matchedUser, matchedCidr, "allowed");
            }

            return isIPv6 ? _v6AllOwner is not null ? (_v6AllOwner, "::/0", "allowed") : (null, null, "not found")
                   : _v4AllOwner is not null ? (_v4AllOwner, "0.0.0.0/0", "allowed") : (null, null, "not found");
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    /// <summary>
    ///     Gets all networks associated with a user.
    /// </summary>
    /// <param name="username">The user ID. </param>
    /// <returns>Enumerable of CIDR strings.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static IEnumerable<string> GetUserNetworks(string username) => _userToCidrsIndex.TryGetValue(username, out ConcurrentHashSet<string>? set) ? set.Keys.ToArray() : [];

    /// <summary>
    ///     Gets the global deny list.
    /// </summary>
    /// <returns>Enumerable of CIDR strings in the deny list.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static IEnumerable<string> GetGlobalDenyList() => _globalDenyList.Select(entry => ToCidrString(entry.Key.Net, entry.Key.Prefix, entry.Key.IsIPv6)).ToArray();

    /// <summary>
    ///     Checks if an IP address is in the deny list.
    /// </summary>
    /// <param name="ip">The IP address as a byte span.</param>
    /// <param name="isIPv6">True if the IP is IPv6, false for IPv4.</param>
    /// <returns>True if the IP is in the deny list, false otherwise.</returns>
    private static bool IsInDenyList(ReadOnlySpan<byte> ip, bool isIPv6)
    {
        int bucket = isIPv6 ? (ip[0] << 8) | ip[1] : ip[0];
        ConcurrentDictionary<int, ConcurrentHashSet<DenyEntry>> dict = isIPv6 ? _denyListIPv6Buckets : _denyListIPv4Buckets;
        if (!dict.TryGetValue(bucket, out ConcurrentHashSet<DenyEntry>? set))
        {
            return false;
        }

        foreach (KeyValuePair<DenyEntry, byte> e in set)
        {
            if (e.Key.IsIPv6 != isIPv6)
            {
                continue;
            }

            int full = e.Key.Prefix >> 3;
            int rem = e.Key.Prefix & 7;

            if (!ip.Slice(0, full).SequenceEqual(e.Key.Net.AsSpan(0, full)))
            {
                continue;
            }

            if (rem == 0)
            {
                return true;
            }

            byte mask = (byte)(0xFF << (8 - rem));
            if ((ip[full] & mask) == (e.Key.Net[full] & mask))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    ///     Parses a CIDR or IP range into a list of CIDRs.
    /// </summary>
    private static (string Ip, int Prefix)[] ParseCidrOrRange(ReadOnlySpan<char> input, out bool isIPv6)
    {
        isIPv6 = input.Contains(':');
        int dash = input.IndexOf('-');
        if (dash >= 0)
        {
            string startIp = input[..dash].Trim().ToString();
            string endIp = input[(dash + 1)..].Trim().ToString();
            if (isIPv6)
            {
                return [];
            }

            return RangeToCidrsIPv4(startIp, endIp);
        }

        int slash = input.IndexOf('/');
        if (slash >= 0)
        {
            string ipPart = input[..slash].ToString();
            if (!int.TryParse(input[(slash + 1)..], out int prefix) || prefix < 0 || prefix > (isIPv6 ? 128 : 32))
            {
                return [];
            }

            return [(ipPart, prefix)];
        }

        return [(input.ToString(), isIPv6 ? 128 : 32)];
    }

    /// <summary>
    ///     Converts an IPv4 range to a list of CIDRs.
    /// </summary>
    private static (string Ip, int Prefix)[] RangeToCidrsIPv4(string start, string end)
    {
        if (!TryParseIpv4ToUint(start, out uint s) || !TryParseIpv4ToUint(end, out uint e) || s > e)
        {
            return [];
        }

        List<(string, int)> res = new();
        while (s <= e)
        {
            int maxLenByAlign = s == 0 ? 32 : 32 - BitOperations.TrailingZeroCount(s);
            int maxLenByRange = 32 - (int)Math.Floor(Math.Log2((e - s) + 1));
            int prefix = Math.Min(maxLenByAlign, maxLenByRange);

            string ip = $"{(s >> 24) & 255}.{(s >> 16) & 255}.{(s >> 8) & 255}.{s & 255}";
            res.Add((ip, prefix));

            uint block = prefix == 32 ? 1u : 1u << (32 - prefix);
            s += block;
        }

        return res.ToArray();
    }

    /// <summary>
    ///     Parses an IPv4 address to uint.
    /// </summary>
    private static bool TryParseIpv4ToUint(string s, out uint value)
    {
        value = 0;
        int octet = 0, octetIdx = 0, digits = 0;
        for (int i = 0; i <= s.Length; i++)
        {
            bool end = i == s.Length;
            char c = end ? '.' : s[i];
            if (c == '.')
            {
                if (digits == 0 || octet > 255 || octetIdx >= 4)
                {
                    return false;
                }

                value = (value << 8) | (uint)octet;
                octet = 0;
                digits = 0;
                octetIdx++;
            }
            else if (c is >= '0' and <= '9')
            {
                if (++digits > 3)
                {
                    return false;
                }

                octet = (octet * 10) + (c - '0');
            }
            else
            {
                return false;
            }
        }

        return octetIdx == 4;
    }

    /// <summary>
    ///     Inserts an IPv4 network into the Trie.
    /// </summary>
    private static void InsertIPv4Network(Span<byte> ipBytes, int prefix, string cidr, string username)
    {
        int first = ipBytes[0];
        if (prefix < IPv4Stride)
        {
            int range = 1 << (IPv4Stride - prefix);
            int startRoot = (first >> (IPv4Stride - prefix)) << (IPv4Stride - prefix);
            for (int root = startRoot; root < startRoot + range; root++)
            {
                _roots4[root] ??= new() { BitIndex = 0 };

                Node current = _roots4[root]!;
                current.IsAllowed = true;
                current.Cidr = cidr;
                current.UserId = username;
            }

            return;
        }

        _roots4[first] ??= new() { BitIndex = 0 };

        Node currentNode = _roots4[first]!;
        for (int bit = IPv4Stride; bit < prefix;)
        {
            int byteIndex = bit / 8;
            int bitIndex = 7 - (bit % 8);
            int bitValue = (ipBytes[byteIndex] >> bitIndex) & 1;
            if (currentNode.Children[bitValue] == null)
            {
                currentNode.Children[bitValue] = new() { BitIndex = bit };
            }
            else if (currentNode.Children[bitValue]!.BitIndex > bit)
            {
                Node newNode = new() { BitIndex = bit, Children = { [bitValue] = currentNode.Children[bitValue] } };
                currentNode.Children[bitValue] = newNode;
            }

            currentNode = currentNode.Children[bitValue]!;
            bit = currentNode.BitIndex + 1;
        }

        currentNode.IsAllowed = true;
        currentNode.Cidr = cidr;
        currentNode.UserId = username;
    }

    /// <summary>
    ///     Inserts an IPv6 network into the Trie.
    /// </summary>
    private static void InsertIPv6Network(Span<byte> ipBytes, int prefix, string cidr, string username)
    {
        int first16 = (ipBytes[0] << 8) | ipBytes[1];
        if (prefix < IPv6Stride)
        {
            int range = 1 << (IPv6Stride - prefix);
            int startRoot = (first16 >> (IPv6Stride - prefix)) << (IPv6Stride - prefix);
            for (int root = startRoot; root < startRoot + range; root++)
            {
                _roots6.GetOrAdd(root, _ => new() { BitIndex = 0 });
                Node current = _roots6[root];
                current.IsAllowed = true;
                current.Cidr = cidr;
                current.UserId = username;
            }

            return;
        }

        _roots6.GetOrAdd(first16, _ => new() { BitIndex = 0 });
        Node currentNode = _roots6[first16];
        for (int bit = IPv6Stride; bit < prefix;)
        {
            int byteIndex = bit / 8;
            int bitIndex = 7 - (bit % 8);
            int bitValue = (ipBytes[byteIndex] >> bitIndex) & 1;
            if (currentNode.Children[bitValue] == null)
            {
                currentNode.Children[bitValue] = new() { BitIndex = bit };
            }
            else if (currentNode.Children[bitValue]!.BitIndex > bit)
            {
                Node newNode = new() { BitIndex = bit, Children = { [bitValue] = currentNode.Children[bitValue] } };
                currentNode.Children[bitValue] = newNode;
            }

            currentNode = currentNode.Children[bitValue]!;
            bit = currentNode.BitIndex + 1;
        }

        currentNode.IsAllowed = true;
        currentNode.Cidr = cidr;
        currentNode.UserId = username;
    }

    /// <summary>
    ///     Converts a byte array and prefix to a CIDR string.
    /// </summary>
    private static string ToCidrString(ReadOnlySpan<byte> ipBytes, int prefix, bool isIPv6)
    {
        if (!isIPv6)
        {
            return $"{ipBytes[0]}.{ipBytes[1]}.{ipBytes[2]}.{ipBytes[3]}/{prefix}";
        }

        Span<ushort> h = stackalloc ushort[8];
        for (int i = 0; i < 8; i++)
        {
            h[i] = (ushort)((ipBytes[i * 2] << 8) | ipBytes[(i * 2) + 1]);
        }

        int bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
        for (int i = 0; i < 8; i++)
        {
            if (h[i] == 0)
            {
                if (curStart < 0)
                {
                    curStart = i;
                    curLen = 1;
                }
                else
                {
                    curLen++;
                }

                if (curLen > bestLen)
                {
                    bestLen = curLen;
                    bestStart = curStart;
                }
            }
            else
            {
                curStart = -1;
                curLen = 0;
            }
        }

        if (bestLen < 2)
        {
            bestStart = -1;
        }

        StringBuilder sb = new(64);
        for (int i = 0; i < 8;)
        {
            if (i == bestStart)
            {
                sb.Append("::");
                i += bestLen;
                if (i >= 8)
                {
                    break;
                }

                if (i is > 0 and < 8 && sb[^1] != ':')
                {
                    sb.Append(':');
                }
            }
            else
            {
                sb.Append(h[i].ToString("x"));
                i++;
                if (i < 8 && i != bestStart)
                {
                    sb.Append(':');
                }
            }
        }

        sb.Append('/').Append(prefix);
        return sb.ToString();
    }

    /// <summary>
    ///     Applies a netmask to an IP address byte array.
    /// </summary>
    private static void ApplyNetmask(Span<byte> bytes, int prefix)
    {
        int full = prefix >> 3;
        int rem = prefix & 7;
        for (int i = full + (rem > 0 ? 1 : 0); i < bytes.Length; i++)
        {
            bytes[i] = 0;
        }

        if (rem > 0)
        {
            bytes[full] &= (byte)(0xFF << (8 - rem));
        }
    }

    /// <summary>
    ///     Parses an IP address string into a byte array.
    /// </summary>
    private static bool TryParseIp(ReadOnlySpan<char> ipSpan, Span<byte> ipBytes, bool isIPv6)
    {
        if (!isIPv6)
        {
            return TryParseIpv4(ipSpan, ipBytes);
        }

        Span<ushort> span = stackalloc ushort[8];
        int index = 0, start = 0, doubleColonIndex = -1;
        for (int i = 0; i <= ipSpan.Length; i++)
        {
            bool atEnd = i == ipSpan.Length;
            if (!atEnd && ipSpan[i] != ':')
            {
                continue;
            }

            int len = i - start;
            if (len == 0)
            {
                if (!atEnd && i + 1 < ipSpan.Length && ipSpan[i + 1] == ':')
                {
                    if (doubleColonIndex >= 0)
                    {
                        return false;
                    }

                    doubleColonIndex = index;
                    i++;
                    start = i + 1;
                    continue;
                }

                if (doubleColonIndex < 0)
                {
                    return false;
                }

                start = i + 1;
                continue;
            }

            if (index >= 8 || !TryParseHex(ipSpan.Slice(start, len), out span[index++]))
            {
                return false;
            }

            start = i + 1;
        }

        if (doubleColonIndex >= 0)
        {
            int missing = 8 - index;
            for (int j = index - 1; j >= doubleColonIndex; j--)
            {
                span[j + missing] = span[j];
            }

            for (int j = doubleColonIndex; j < doubleColonIndex + missing; j++)
            {
                span[j] = 0;
            }

            index = 8;
        }

        if (index != 8)
        {
            return false;
        }

        for (int i = 0; i < 8; i++)
        {
            ipBytes[i * 2] = (byte)(span[i] >> 8);
            ipBytes[(i * 2) + 1] = (byte)span[i];
        }

        return true;
    }

    /// <summary>
    ///     Parses an IPv4 address string into a byte array.
    /// </summary>
    private static bool TryParseIpv4(ReadOnlySpan<char> s, Span<byte> ipBytes)
    {
        int octet = 0, octetIdx = 0, digits = 0;
        for (int i = 0; i <= s.Length; i++)
        {
            bool end = i == s.Length;
            char c = end ? '.' : s[i];
            if (c == '.')
            {
                if (digits == 0 || octet > 255 || octetIdx >= 4)
                {
                    return false;
                }

                ipBytes[octetIdx++] = (byte)octet;
                octet = 0;
                digits = 0;
            }
            else if (c is >= '0' and <= '9')
            {
                if (++digits > 3)
                {
                    return false;
                }

                octet = (octet * 10) + (c - '0');
            }
            else
            {
                return false;
            }
        }

        return octetIdx == 4;
    }

    /// <summary>
    ///     Parses a hexadecimal string into ushort.
    /// </summary>
    private static bool TryParseHex(ReadOnlySpan<char> hex, out ushort value)
    {
        value = 0;
        if (hex.Length is 0 or > 4)
        {
            return false;
        }

        foreach (char c in hex)
        {
            if (c is >= '0' and <= '9')
            {
                value = (ushort)((value << 4) | (c - '0'));
            }
            else if (c is >= 'a' and <= 'f')
            {
                value = (ushort)((value << 4) | ((c - 'a') + 10));
            }
            else if (c is >= 'A' and <= 'F')
            {
                value = (ushort)((value << 4) | ((c - 'A') + 10));
            }
            else
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    ///     Extracts the IP address from an X-Forwarded-For header or raw IP string.
    /// </summary>
    private static ReadOnlySpan<char> ExtractIpSpan(ReadOnlySpan<char> raw)
    {
        int comma = raw.IndexOf(',');
        ReadOnlySpan<char> s = comma >= 0 ? raw[..comma] : raw;
        while (!s.IsEmpty && char.IsWhiteSpace(s[0]))
        {
            s = s[1..];
        }

        while (!s.IsEmpty && char.IsWhiteSpace(s[^1]))
        {
            s = s[..^1];
        }

        if (!s.IsEmpty && s[0] == '[')
        {
            int close = s.IndexOf(']');
            if (close > 0)
            {
                s = s.Slice(1, close - 1);
            }
        }

        int pct = s.IndexOf('%');
        if (pct >= 0)
        {
            s = s[..pct];
        }

        int lastColon = s.LastIndexOf(':');
        if (s.Contains('.') && lastColon > 0)
        {
            bool allDigits = true;
            for (int i = lastColon + 1; i < s.Length; i++)
            {
                if (s[i] < '0' || s[i] > '9')
                {
                    allDigits = false;
                    break;
                }
            }

            if (allDigits)
            {
                s = s[..lastColon];
            }
        }

        return s;
    }

    /// <summary>
    /// Checks if a single IP exists in any user-registered subnets.
    /// Returns whether it exists, matched username, matched CIDR and reason.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static (bool Exists, string? Username, string? Cidr, string Reason) ContainsIp(ReadOnlySpan<char> ip)
    {
        if (ip.IsEmpty)
        {
            return (false, null, null, "invalid input");
        }

        ReadOnlySpan<char> ipSpan = ExtractIpSpan(ip);
        if (ipSpan.IsEmpty)
        {
            return (false, null, null, "invalid IP");
        }

        bool isIPv6 = ipSpan.Contains(':');
        Span<byte> ipBytes = stackalloc byte[isIPv6 ? 16 : 4];

        if (ip.ContainsAny("/"))
        {
            int slash = ip.IndexOf('/');
            if (slash >= 0)
            {
                if (!int.TryParse(ip[(slash + 1)..], out int prefix) || prefix < 0 || prefix > (isIPv6 ? 128 : 32))
                {
                    return (false, null, null, "invalid IP");
                }
            }
        }
        else if (!TryParseIp(ipSpan, ipBytes, isIPv6))
        {
            return (false, null, null, "invalid IP");
        }

        _lock.EnterReadLock();
        try
        {
            if (IsInDenyList(ipBytes, isIPv6))
            {
                return (false, null, null, "blacklisted");
            }

            Node? current;
            string? matchedUser = null, matchedCidr = null;
            if (isIPv6)
            {
                if (_v6AllOwner is not null)
                {
                    return (true, _v6AllOwner, "::/0", "allowed");
                }

                if (!_roots6.TryGetValue((ipBytes[0] << 8) | ipBytes[1], out current))
                {
                    return (false, null, null, "not found");
                }
            }
            else
            {
                if (_v4AllOwner is not null)
                {
                    return (true, _v4AllOwner, "0.0.0.0/0", "allowed");
                }

                if (_roots4[ipBytes[0]] == null)
                {
                    return (false, null, null, "not found");
                }

                current = _roots4[ipBytes[0]];
            }

            if (current == null)
            {
                return (false, null, null, "not found");
            }

            int startBit = isIPv6 ? IPv6Stride : IPv4Stride;

            int bit = startBit;
            while (bit < ipBytes.Length * 8)
            {
                if (current is { IsAllowed: true, UserId: not null })
                {
                    matchedUser = current.UserId;
                    matchedCidr = current.Cidr;
                }
                int byteIndex = bit / 8;
                int bitIndex = 7 - (bit % 8);
                int bitValue = (ipBytes[byteIndex] >> bitIndex) & 1;
                current = current.Children[bitValue];

                if (current == null)
                {
                    break;
                }

                bit = current.BitIndex + 1;
            }

            if (current is { IsAllowed: true, UserId: not null })
            {
                matchedUser = current.UserId;
                matchedCidr = current.Cidr;
            }

            if (matchedUser != null)
            {
                return (true, matchedUser, matchedCidr, "found in user subnet");
            }

            return (false, null, null, "not found");
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    /// <summary>
    /// Checks whether a CIDR overlaps with any user-registered subnet.
    /// If plain IP given, redirects to <see cref="ContainsIp"/>.
    /// </summary>
    public static (bool Exists, string? Username, string? Cidr, string Reason) ContainsCidr(string cidr)
    {
        if (!cidr.Contains('/'))
        {
            // Input was a plain IP → pass it to the previous method
            return ContainsIp(cidr);
        }

        string[] parts = cidr.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out IPAddress? baseIp) || !int.TryParse(parts[1], out int prefix))
        {
            return (false, null, null, "invalid CIDR");
        }

        bool isIPv6 = baseIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        Span<byte> ipBytes = stackalloc byte[isIPv6 ? 16 : 4];
        baseIp.GetAddressBytes().CopyTo(ipBytes);

        _lock.EnterReadLock();
        try
        {
            Node? current;
            if (isIPv6)
            {
                if (_v6AllOwner is not null)
                {
                    return (true, _v6AllOwner, "::/0", "allowed");
                }

                if (!_roots6.TryGetValue((ipBytes[0] << 8) | ipBytes[1], out current))
                {
                    return (false, null, null, "not found");
                }
            }
            else
            {
                if (_v4AllOwner is not null)
                {
                    return (true, _v4AllOwner, "0.0.0.0/0", "allowed");
                }

                current = _roots4[ipBytes[0]];
                if (current == null)
                {
                    return (false, null, null, "not found");
                }
            }

            // Traverse the prefix path
            int bit = isIPv6 ? IPv6Stride : IPv4Stride;
            int maxBits = ipBytes.Length * 8;

            while (bit < prefix && bit < maxBits && current != null)
            {
                if (current.IsAllowed && current.UserId is not null)
                {
                    return (true, current.UserId, current.Cidr, "found in subnet");
                }

                int byteIndex = bit / 8;
                int bitIndex = 7 - (bit % 8);
                int bitValue = (ipBytes[byteIndex] >> bitIndex) & 1;
                current = current.Children[bitValue];
                bit = current?.BitIndex + 1 ?? maxBits;
            }

            // Input was a plain IP → pass it to the previous method
            if (current != null)
            {
                Node? found = FindAnyAllowedInSubtree(current);
                if (found != null)
                {
                    return (true, found.UserId, found.Cidr, $"found in CIDR {cidr}");
                }
            }

            return (false, null, cidr, "no IP found in CIDR");
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    private static Node? FindAnyAllowedInSubtree(Node node)
    {
        if (node is { IsAllowed: true, UserId: not null })
        {
            return node;
        }

        if (node.Children[0] != null)
        {
            Node? f = FindAnyAllowedInSubtree(node.Children[0]!);
            if (f != null)
            {
                return f;
            }
        }
        if (node.Children[1] != null)
        {
            Node? f = FindAnyAllowedInSubtree(node.Children[1]!);
            if (f != null)
            {
                return f;
            }
        }

        return null;
    }

    /// <summary>
    /// Normalizes a CIDR by adjusting the IP address to the network address.
    /// </summary>
    /// <param name="cidr">The CIDR to normalize (e.g., "91.199.9.90/28").
    /// <returns>The normalized CIDR string (e.g., "91.199.9.80/28") or an empty string if invalid.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static string NormalizeCidr(ReadOnlySpan<char> cidr)
    {
        (string Ip, int Prefix)[] cidrs = ParseCidrOrRange(cidr, out bool isIPv6);
        if (cidrs.Length != 1)
        {
            return string.Empty; // Only single CIDR is supported, not ranges
        }

        (string ip, int prefix) = cidrs[0];
        Span<byte> ipBytes = stackalloc byte[isIPv6 ? 16 : 4];
        if (!TryParseIp(ip.AsSpan(), ipBytes, isIPv6))
        {
            return string.Empty;
        }

        ApplyNetmask(ipBytes, prefix);
        return ToCidrString(ipBytes, prefix, isIPv6);
    }

    /// <summary>
    /// Finds all overlaps between a given IP/CIDR and user-registered CIDRs.
    /// Returns a list of (UserId, Cidr).
    /// </summary>
    public static List<(string UserId, string Cidr)> FindOverlaps(string ipOrCidr)
    {
        List<(string UserId, string Cidr)> results = [];

        // Single IP mode
        if (!ipOrCidr.Contains('/'))
        {
            if (!IPAddress.TryParse(ipOrCidr, out IPAddress? ip))
            {
                return results;
            }

            CollectAllOverlaps(ip, results);
            return results;
        }

        // CIDR mode
        string[] parts = ipOrCidr.Split('/');
        if (parts.Length != 2 ||
            !IPAddress.TryParse(parts[0], out IPAddress? baseIp) ||
            !int.TryParse(parts[1], out int prefix))
        {
            return results;
        }

        CollectAllCidrOverlaps(baseIp, prefix, results);

        return results;
    }

    private static void CollectAllOverlaps(IPAddress ip, List<(string UserId, string Cidr)> results)
    {
        byte[] ipBytes = ip.GetAddressBytes();
        bool isIPv6 = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;

        Node? root;
        if (!isIPv6)
        {
            root = _roots4[ipBytes[0]];
            if (root == null)
            {
                return;
            }
        }
        else
        {
            int rootKey = (ipBytes[0] << 8) | ipBytes[1];
            if (rootKey >= _roots6.Count || (root = _roots6[rootKey]) == null)
            {
                return;
            }
        }

        TraverseAllOverlaps(root, ipBytes, 0, ipBytes.Length * 8, results);
    }

    private static void CollectAllCidrOverlaps(IPAddress baseIp, int prefix, List<(string UserId, string Cidr)> results)
    {
        byte[] ipBytes = baseIp.GetAddressBytes();
        bool isIPv6 = baseIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;

        Node? root;
        if (!isIPv6)
        {
            root = _roots4[ipBytes[0]];
            if (root == null)
            {
                return;
            }
        }
        else
        {
            int rootKey = (ipBytes[0] << 8) | ipBytes[1];
            if (rootKey >= _roots6.Count || (root = _roots6[rootKey]) == null)
            {
                return;
            }
        }

        TraverseAllCidrOverlaps(root, ipBytes, prefix, 0, results);
    }

    private static void TraverseAllOverlaps(Node? node, byte[] ipBytes, int depth, int maxDepth, List<(string UserId, string Cidr)> results)
    {
        if (node == null)
        {
            return;
        }

        if (node is { IsAllowed: true, UserId: not null, Cidr: not null })
        {
            results.Add((node.UserId, node.Cidr));
        }

        if (depth >= maxDepth)
        {
            return;
        }

        int byteIndex = depth / 8;
        int bitIndex = 7 - (depth % 8);
        int bitValue = (ipBytes[byteIndex] >> bitIndex) & 1;

        // Main bit path
        TraverseAllOverlaps(node.Children[bitValue], ipBytes, depth + 1, maxDepth, results);

        // Opposite path → to find all overlapping nodes (/32, etc.)
        TraverseAllOverlaps(node.Children[1 - bitValue], ipBytes, depth + 1, maxDepth, results);
    }

    private static void TraverseAllCidrOverlaps(Node? node, byte[] ipBytes, int prefix, int depth, List<(string UserId, string Cidr)> results)
    {
        if (node == null)
        {
            return;
        }

        if (node is { IsAllowed: true, UserId: not null, Cidr: not null })
        {
            results.Add((node.UserId, node.Cidr));
        }

        if (depth >= prefix)
        {
            return;
        }

        int byteIndex = depth / 8;
        int bitIndex = 7 - (depth % 8);
        int bitValue = (ipBytes[byteIndex] >> bitIndex) & 1;

        // Main bit path
        TraverseAllCidrOverlaps(node.Children[bitValue], ipBytes, prefix, depth + 1, results);

        // Opposite path → for all overlapping nodes
        TraverseAllCidrOverlaps(node.Children[1 - bitValue], ipBytes, prefix, depth + 1, results);
    }

    /// <summary>
    ///     A thread-safe hash set implementation for storing items.
    /// </summary>
    private class ConcurrentHashSet<T> : ConcurrentDictionary<T, byte> where T : notnull
    {
        /// <summary>
        ///     Gets whether the set is empty.
        /// </summary>
        public new bool IsEmpty => base.IsEmpty;

        /// <summary>
        ///     Adds an item to the set.
        /// </summary>
        public bool Add(T item) => TryAdd(item, 0);

        /// <summary>
        ///     Removes an item from the set.
        /// </summary>
        public bool TryRemove(T item) => TryRemove(item, out _);
    }
}