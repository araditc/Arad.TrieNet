# Arad.TrieNet

![GitHub License](https://img.shields.io/github/license/araditc/Arad.TrieNet)
![NuGet Version](https://img.shields.io/nuget/v/Arad.TrieNet)

Arad.TrieNet is an ultra-fast, thread-safe, and scalable IP filtering library designed for high-performance network access control. Powered by a Trie-based data structure, it handles 100,000+ requests per second with minimal latency, making it ideal for fraud prevention and network security in multi-tenant systems.

## Features
- **Blazing Fast Lookups**: O(log n) time complexity for IP matching using Longest Prefix Match (LPM).
- **IPv4 & IPv6 Support**: Efficiently manages CIDR-based networks, single IPs, and ranges.
- **Global Deny List**: Bucket-based deny list with priority over allow rules for enhanced security.
- **Per-User Management**: Supports up to 200,000 users with average 5 IPs/CIDRs/ranges per user.
- **Thread-Safe**: Utilizes `ReaderWriterLockSlim` for concurrent reads/writes.
- **Memory Efficient**: Less than 50MB for 1M CIDRs and 200,000 users.
- **No GC Pressure**: Allocation-free lookups with stack-allocated buffers.

## Installation
You can install Arad.TrieNet via NuGet Package Manager:

```bash
dotnet add package Arad.TrieNet
```

## Usage
### Adding a Network
```csharp
using Arad.TrieNet.Core;

// Add a CIDR network to a user's allowed list
IPFilter.AddNetwork("192.168.1.0/24", "user1");

// Add a range to a user's allowed list
IPFilter.AddNetwork("192.168.1.1-192.168.1.10", "user1");
```

### Adding to Global Deny List
```csharp
// Add a CIDR to the global deny list
IPFilter.AddDeny("10.0.0.0/8");

// Add a single IP to the global deny list
IPFilter.AddDeny("10.1.2.3");
```

### Checking if an IP is Allowed
```csharp
var (isAllowed, reason) = IPFilter.IsAllowed("user1", "192.168.1.5");
Console.WriteLine($"Is Allowed: {isAllowed}, Reason: {reason}"); // Output: Is Allowed: True, Reason: allowed
```

### Finding the Owner of an IP
```csharp
var (owner, reason) = IPFilter.FindOwner("192.168.1.5");
Console.WriteLine($"Owner: {owner}, Reason: {reason}"); // Output: Owner: user1, Reason: allowed
```

### Finding Owner with CIDR
```csharp
var (owner, cidr, reason) = IPFilter.FindOwnerWithCidr("192.168.1.5");
Console.WriteLine($"Owner: {owner}, CIDR: {cidr}, Reason: {reason}"); // Output: Owner: user1, CIDR: 192.168.1.0/30, Reason: allowed
```

### Getting User Networks
```csharp
var networks = IPFilter.GetUserNetworks("user1");
foreach (var network in networks)
{
    Console.WriteLine(network); // Output: 91.199.9.60/32, 185.37.54.112/27, etc.
}
```

### Getting Global Deny List
```csharp
var denyList = IPFilter.GetGlobalDenyList();
foreach (var deniedCidr in denyList)
{
    Console.WriteLine(deniedCidr); // Output: 192.168.1.0/24, etc.
}
```

## Performance
- **Trie-based Lookups**: O(log n) for IP matching, optimized for 100,000 RPS.
- **Deny List**: Bucket-based with FNV-like hashing for low-latency checks.
- **Memory Usage**: <50MB for 1M CIDRs and 200,000 users.
- **No Allocations**: Stack-allocated buffers in critical paths to minimize GC pressure.

Benchmark results (using BenchmarkDotNet):
- IsAllowed: ~5ns per call.
- FindOwner: ~10ns per call.

## Documentation
- [API Reference](docs/api.md)
- [Performance Details](docs/performance.md)
- [Usage Guide](docs/usage.md)

## Contributing
Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute, report issues, or submit pull requests.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.