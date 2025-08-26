
namespace Arad.TrieNet;

/// <summary>
/// Represents an entry in the deny list for IP filtering.
/// </summary>
/// <remarks>
/// This struct stores an IP network (IPv4 or IPv6) with its prefix length for efficient deny list lookups.
/// Uses a lightweight FNV-like hash for low collision rates in ConcurrentDictionary/ConcurrentHashSet.
/// </remarks>
public readonly struct DenyEntry : IEquatable<DenyEntry>
{
    /// <summary>
    /// Indicates whether the entry is for an IPv6 address.
    /// </summary>
    public readonly bool IsIPv6;

    /// <summary>
    /// The network address as a byte array (4 bytes for IPv4, 16 bytes for IPv6).
    /// </summary>
    public readonly byte[] Net;

    /// <summary>
    /// The prefix length of the network (e.g., 24 for /24 CIDR).
    /// </summary>
    public readonly int Prefix;

    /// <summary>
    /// Initializes a new DenyEntry.
    /// </summary>
    /// <param name="isIPv6">True if the network is IPv6, false for IPv4. </param>
    /// <param name="net">The network address as a byte array.</param>
    /// <param name="prefix">The prefix length of the network. </param>
    public DenyEntry(bool isIPv6, byte[] net, int prefix)
    {
        IsIPv6 = isIPv6;
        Net = net;
        Prefix = prefix;
    }

    /// <summary>
    /// Determines whether this DenyEntry equals another.
    /// </summary>
    /// <param name="other">The other DenyEntry to compare with. </param>
    /// <returns>True if the entries are equal, false otherwise. </returns>
    public bool Equals(DenyEntry other) =>
        IsIPv6 == other.IsIPv6 && Prefix == other.Prefix && Net.AsSpan().SequenceEqual(other.Net);

    /// <summary>
    /// Determines whether this DenyEntry equals another object.
    /// </summary>
    /// <param name="obj">The object to compare with. </param>
    /// <returns>True if the object is a DenyEntry and equal, false otherwise.</returns>
    public override bool Equals(object? obj) => obj is DenyEntry entry && Equals(entry);

    /// <summary>
    /// Generates a hash code for the DenyEntry using an FNV-like algorithm.
    /// </summary>
    /// <remarks>
    /// Uses up to 16 bytes of the network address for better distribution in hash tables.
    /// </remarks>
    /// <returns>The hash code.</returns>
    public override int GetHashCode()
    {
        unchecked
        {
            int h = HashCode.Combine(IsIPv6, Prefix, Net.Length);
            int len = Math.Min(Net.Length, 16); // Up to 16 bytes for IPv6
            for (int i = 0; i < len; i++)
            {
                h = (h * 16777619) ^ Net[i]; // FNV-like
            }

            return h;
        }
    }
}