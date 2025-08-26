// See https://aka.ms/new-console-template for more information

using Arad.TrieNet;

Console.WriteLine("IPFilter tests:");
Console.WriteLine("IsAllowed:");
(bool allowed, string reason) = IPFilter.IsAllowed("user1", "185.37.54.116");
Console.WriteLine($"IsAllowed(user1, 185.37.54.116): {allowed}, Reason: {reason}");
(allowed, reason) = IPFilter.IsAllowed("user1", "192.168.1.1");
Console.WriteLine($"IsAllowed(user1, 192.168.1.1): {allowed}, Reason: {reason}");
(allowed, reason) = IPFilter.IsAllowed("user2", "fe80::1");
Console.WriteLine($"IsAllowed(user2, fe80::1): {allowed}, Reason: {reason}");
(allowed, reason) = IPFilter.IsAllowed("user3", "10.1.2.3");
Console.WriteLine($"IsAllowed(user3, 10.1.2.3): {allowed}, Reason: {reason}");
(allowed, reason) = IPFilter.IsAllowed("admin", "172.16.0.1");
Console.WriteLine($"IsAllowed(admin, 172.16.0.1): {allowed}, Reason: {reason}");
(allowed, reason) = IPFilter.IsAllowed("user1", "192.168.1.5");
Console.WriteLine($"IsAllowed(user1, 192.168.1.5): {allowed}, Reason: {reason}");

Console.WriteLine("FindOwner:");
(string? owner, string ownerReason) = IPFilter.FindOwner("185.37.54.116");
Console.WriteLine($"FindOwner(185.37.54.116): {owner}, Reason: {ownerReason}");
(owner, ownerReason) = IPFilter.FindOwner("192.168.1.1");
Console.WriteLine($"FindOwner(192.168.1.1): {owner}, Reason: {ownerReason}");
(owner, ownerReason) = IPFilter.FindOwner("fe80::1");
Console.WriteLine($"FindOwner(fe80::1): {owner}, Reason: {ownerReason}");
(owner, ownerReason) = IPFilter.FindOwner("172.16.0.1");
Console.WriteLine($"FindOwner(172.16.0.1): {owner}, Reason: {ownerReason}");
(owner, ownerReason) = IPFilter.FindOwner("192.168.1.5");
Console.WriteLine($"FindOwner(192.168.1.5): {owner}, Reason: {ownerReason}");

Console.WriteLine("FindOwnerWithCidr:");
(string? ownerCidr, string? cidr, string cidrReason) = IPFilter.FindOwnerWithCidr("185.37.54.116");
Console.WriteLine($"FindOwnerWithCidr(185.37.54.116): Owner: {ownerCidr}, CIDR: {cidr}, Reason: {cidrReason}");
(ownerCidr, cidr, cidrReason) = IPFilter.FindOwnerWithCidr("192.168.1.1");
Console.WriteLine($"FindOwnerWithCidr(192.168.1.1): Owner: {ownerCidr}, CIDR: {cidr}, Reason: {cidrReason}");
(ownerCidr, cidr, cidrReason) = IPFilter.FindOwnerWithCidr("172.16.0.1");
Console.WriteLine($"FindOwnerWithCidr(172.16.0.1): Owner: {ownerCidr}, CIDR: {cidr}, Reason: {cidrReason}");
(ownerCidr, cidr, cidrReason) = IPFilter.FindOwnerWithCidr("192.168.1.5");
Console.WriteLine($"FindOwnerWithCidr(192.168.1.5): Owner: {ownerCidr}, CIDR: {cidr}, Reason: {cidrReason}");

Console.WriteLine("GetUserNetworks:");
Console.WriteLine("user1 networks:");
foreach (string network in IPFilter.GetUserNetworks("user1"))
{
    Console.WriteLine(network);
}

Console.WriteLine("user3 networks:");
foreach (string network in IPFilter.GetUserNetworks("user3"))
{
    Console.WriteLine(network);
}

IEnumerable<string> unknownNetworks = IPFilter.GetUserNetworks("unknown");
Console.WriteLine($"unknownNetworks.Any(): {unknownNetworks.Any()}");

Console.WriteLine("GetGlobalDenyList:");
foreach (string item in IPFilter.GetGlobalDenyList())
{
    Console.WriteLine(item);
}

Console.WriteLine("global deny list:");
IPFilter.AddDeny("10.1.2.3");
(allowed, reason) = IPFilter.IsAllowed("user3", "10.1.2.3");
Console.WriteLine($"IsAllowed(user3, 10.1.2.3): {allowed}, Reason: {reason}");
IPFilter.RemoveDeny("10.1.2.3");
(allowed, reason) = IPFilter.IsAllowed("user3", "10.1.2.3");
Console.WriteLine($"IsAllowed(user3, 10.1.2.3): {allowed}, Reason: {reason}");

