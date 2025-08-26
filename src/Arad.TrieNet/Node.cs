namespace Arad.TrieNet;

/// <summary>
/// Represents a node in the Trie data structure for IP filtering.
/// </summary>
/// <remarks>
/// Each node stores information about an IP network's permission status and its children in the Trie.
/// </remarks>
internal sealed class Node
{
    /// <summary>
    /// Indicates whether the IP network represented by this node is allowed.
    /// </summary>
    public bool IsAllowed;

    /// <summary>
    /// The CIDR notation of the IP network (e.g., "192.168.1.0/24").
    /// </summary>
    public string? Cidr;

    /// <summary>
    /// The user ID associated with this IP network.
    /// </summary>
    public string? UserId;

    /// <summary>
    /// The children nodes in the Trie (0 or 1 for binary bits).
    /// </summary>
    public Node?[] Children = new Node?[2];

    /// <summary>
    /// The bit index in the IP address this node represents.
    /// </summary>
    public int BitIndex;
}

