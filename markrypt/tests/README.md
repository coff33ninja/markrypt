# Markrypt Test Suite

This directory contains the comprehensive test suite for the Markrypt package.

## Structure

```
tests/
├── __init__.py              # Tests package
├── README.md               # This file
├── test_runner.py          # Main test runner
├── test_core.py           # Core functionality tests
├── test_high_level.py     # High-level API tests
├── test_cli.py            # CLI tools tests
├── fixtures/              # Test data files
│   ├── small_text.txt     # Small test text
│   ├── large_text.txt     # Large Lorem ipsum text
│   ├── unicode_text.txt   # Unicode and emoji text
│   ├── single_char.txt    # Single character
│   └── empty_text.txt     # Empty file
└── output/                # Test results and outputs
    └── .gitkeep
```

## Running Tests

### Via CLI (Recommended)

```bash
# Quick smoke tests (fastest)
markrypt test --level quick

# Standard test suite (recommended)
markrypt test --level standard

# Comprehensive tests (all tests)
markrypt test --level comprehensive

# Performance benchmarks
markrypt test --level performance

# Custom output directory
markrypt test --level standard --output-dir ./my-results
```

### Direct Execution

```bash
# Run specific test modules
python markrypt-package/markrypt/tests/test_core.py
python markrypt-package/markrypt/tests/test_high_level.py
python markrypt-package/markrypt/tests/test_cli.py

# Run test runner directly
python markrypt-package/markrypt/tests/test_runner.py --level comprehensive
```

## Test Levels

### Quick Tests (--level quick)

- **Duration**: ~5-10 seconds
- **Purpose**: Smoke tests to verify basic functionality
- **Tests**: Essential encryption/decryption operations
- **Use case**: Quick verification during development

### Standard Tests (--level standard) [Default]

- **Duration**: ~30-60 seconds
- **Purpose**: Core functionality verification
- **Tests**: Most important features and edge cases
- **Use case**: Regular testing and CI/CD

### Comprehensive Tests (--level comprehensive)

- **Duration**: ~2-5 minutes
- **Purpose**: Full test coverage including CLI tools
- **Tests**: All available tests including file operations
- **Use case**: Pre-release testing and thorough validation

### Performance Tests (--level performance)

- **Duration**: ~1-2 minutes
- **Purpose**: Performance benchmarking
- **Tests**: Speed tests with different text sizes
- **Use case**: Performance regression testing

## Test Categories

### Core Functionality (`test_core.py`)

- Basic encryption/decryption
- Noise generation and styles
- Unicode handling
- Key validation
- Integrity checking
- Symbol preservation
- Reproducibility with seeds

### High-Level API (`test_high_level.py`)

- MarkryptEncryptor/MarkryptDecryptor classes
- File operations
- Batch processing
- Safe decryption
- Analysis features
- Error handling

### CLI Tools (`test_cli.py`)

- Main CLI (`markrypt`)
- Dedicated tools (`markrypt-encrypt`, `markrypt-decrypt`)
- File-based operations
- Command-line argument parsing

## Test Fixtures

The `fixtures/` directory contains various test data:

- **small_text.txt**: Multi-line text with special characters
- **large_text.txt**: Lorem ipsum text (3000+ characters)
- **unicode_text.txt**: Unicode characters, emojis, and international text
- **single_char.txt**: Single character for edge case testing
- **empty_text.txt**: Empty file for validation testing

## Output Files

Test results are saved to the `output/` directory:

- **JSON Results**: Detailed test results with timestamps
- **Performance Data**: Benchmark results and timing information
- **Temporary Files**: Created during file operation tests

## Writing New Tests

### Adding Core Tests

```python
# In test_core.py
def test_new_feature(self):
    """Test description"""
    mk = markrypt.Markrypt()
    # Test implementation
    self.assertEqual(expected, actual)
```

### Adding High-Level Tests

```python
# In test_high_level.py
def test_new_api_feature(self):
    """Test description"""
    encryptor = MarkryptEncryptor()
    # Test implementation
    self.assertTrue(condition)
```

### Adding CLI Tests

```python
# In test_cli.py
def test_new_cli_feature(self):
    """Test description"""
    cmd = ['markrypt', 'new-command', '--option']
    result = self.run_cli_command(cmd)
    self.assertEqual(0, result.returncode)
```

## Best Practices

1. **Use descriptive test names** that explain what is being tested
2. **Include docstrings** explaining the test purpose
3. **Use appropriate assertions** (assertEqual, assertTrue, etc.)
4. **Clean up temporary files** in test teardown
5. **Test both success and failure cases**
6. **Use fixtures** for consistent test data
7. **Keep tests independent** - no test should depend on another

## Continuous Integration

The test suite is designed to work in CI/CD environments:

```yaml
# Example GitHub Actions
- name: Run Markrypt Tests
  run: |
    pip install -e markrypt-package
    markrypt test --level comprehensive --output-dir ./test-results
```

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure the markrypt package is properly installed
2. **Missing Fixtures**: Check that `markrypt-package/markrypt/tests/fixtures/` contains all required files
3. **Permission Errors**: Ensure write access to the test output directory
4. **CLI Not Found**: Make sure the package is installed (`pip install -e markrypt-package`)
5. **Unicode Errors**: Test fixtures use UTF-8 encoding - ensure your system supports it

### Debug Mode

For detailed debugging, run individual test files:

```bash
python -m unittest markrypt-package.markrypt.tests.test_core.TestMarkryptCore.test_specific_method -v
```
