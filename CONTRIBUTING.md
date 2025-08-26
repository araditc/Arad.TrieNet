# Contributing to Arad.TrieNet

Thank you for considering contributing to Arad.TrieNet! We welcome contributions from the community to help improve this ultra-fast IP filtering library. Whether you're reporting bugs, suggesting features, or submitting pull requests, your input is valuable in making Arad.TrieNet better for everyone.

## Code of Conduct
This project adheres to a Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to [info@arad-itc.org].

## How to Contribute
### Reporting Bugs
- Check if the bug has already been reported in the [Issues](https://github.com/araditc/Arad.TrieNet/issues) section.
- If not, open a new issue with a clear title and description, including steps to reproduce, expected behavior, and actual behavior.
- Provide as much detail as possible, including the version of Arad.TrieNet, .NET runtime, and any relevant code snippets.

### Suggesting Features
- Open an issue in the [Issues](https://github.com/araditc/Arad.TrieNet/issues) section with the label "enhancement".
- Describe the feature, why it's needed, and how it would benefit the project.
- Be open to discussion and feedback from maintainers and other contributors.

### Submitting Pull Requests
- Fork the repository and create a new branch for your changes (e.g., `feature/new-feature` or `fix/bug-fix`).
- Ensure your code follows the project's style guidelines:
  - Use consistent indentation (4 spaces).
  - Follow C# naming conventions (PascalCase for classes/methods, camelCase for variables).
  - Add XML comments to all public members.
  - Ensure code is thread-safe and optimized for performance.
- Write unit tests for new features or bug fixes using xUnit (see the `tests` directory).
- Run all tests locally to ensure they pass (`dotnet test`).
- Commit your changes with clear, descriptive messages.
- Open a pull request against the `main` branch, describing the changes, referencing any related issues, and explaining why the PR should be merged.
- Be responsive to feedback during the review process.

## Setting Up the Development Environment
- Clone the repository: `git clone https://github.com/araditc/Arad.TrieNet.git`
- Navigate to the project directory: `cd Arad.TrieNet`
- Restore dependencies: `dotnet restore`
- Build the project: `dotnet build`
- Run tests: `dotnet test`

## Style Guidelines
- Follow Microsoft's C# coding conventions.
- Use nullable reference types (`<Nullable>enable</Nullable>`).
- Ensure all public APIs have XML documentation comments.
- Avoid unnecessary allocations; use `Span<T>` and `ReadOnlySpan<T>` where possible.
- Write efficient, thread-safe code.

## Testing
- All new features and bug fixes must be accompanied by unit tests.
- Tests are located in the `tests/Arad.TrieNet.Tests` directory.
- Use xUnit for testing.
- Ensure 100% test coverage for critical paths (e.g., IP parsing, Trie insertions, lookups).

## License
By contributing, you agree that your contributions will be licensed under the MIT License.

Thank you for helping make Arad.TrieNet better!