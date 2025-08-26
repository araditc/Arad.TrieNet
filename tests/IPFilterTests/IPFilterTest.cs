using Xunit;

namespace Arad.TrieNet.Tests;

/// <summary>
/// Unit tests for the UltraFastIPFilter class.
/// </summary>
public class IPFilterTests
{
    /// <summary>
    /// Tests if user1 is allowed for IP 185.37.54.116.
    /// </summary>
    [Fact]
    public void IsAllowed_User1_185_37_54_116_ShouldReturnTrue()
    {
        (bool allowed, string? reason) = IPFilter.IsAllowed("user1", "185.37.54.116");
        Assert.True(allowed);
        Assert.Equal("allowed", reason);
    }

    /// <summary>
    /// Tests if user1 is blocked for IP 192.168.1.1 due to deny list.
    /// </summary>
    [Fact]
    public void IsAllowed_User1_192_168_1_1_ShouldReturnFalse()
    {
        (bool allowed, string? reason) = IPFilter.IsAllowed("user1", "192.168.1.1");
        Assert.False(allowed);
        Assert.Equal("blacklisted", reason);
    }

    /// <summary>
    /// Tests if the owner of IP 185.37.54.116 is user1.
    /// </summary>
    [Fact]
    public void FindOwner_185_37_54_116_ShouldReturnUser1()
    {
        (string? owner, string? reason) = IPFilter.FindOwner("185.37.54.116");
        Assert.Equal("user1", owner);
        Assert.Equal("allowed", reason);
    }

    /// <summary>
    /// Tests if adding IP 10.1.2.3 to deny list blocks access.
    /// </summary>
    [Fact]
    public void AddDeny_10_1_2_3_ShouldBlockAccess()
    {
        IPFilter.AddDeny("10.1.2.3");
        (bool allowed, string? reason) = IPFilter.IsAllowed("user3", "10.1.2.3");
        Assert.False(allowed);
        Assert.Equal("blacklisted", reason);
        IPFilter.RemoveDeny("10.1.2.3");
    }
}