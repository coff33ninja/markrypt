"""
Main CLI interface for Markrypt - combines encrypt, decrypt, and test functionality
"""

import argparse
import sys
import os
from pathlib import Path
from .encrypt.cli import main as encrypt_main
from .decrypt.cli import main as decrypt_main


def run_tests():
    """Run Markrypt tests"""
    # Find tests directory - it's in the same package
    tests_dir = Path(__file__).parent / "tests"
    if not tests_dir.exists():
        print("❌ Tests directory not found.")
        sys.exit(1)
    
    # Add tests to path
    sys.path.insert(0, str(tests_dir))
    
    try:
        from test_runner import MarkryptTestRunner
    except ImportError as e:
        print(f"❌ Could not import test runner: {e}")
        print("Please ensure the markrypt package is properly installed.")
        sys.exit(1)
    
    # Parse test arguments
    parser = argparse.ArgumentParser(
        prog="markrypt test",
        description="Run Markrypt test suite"
    )
    parser.add_argument('--level', choices=['quick', 'standard', 'comprehensive', 'performance'], 
                       default='standard', help='Test level to run (default: standard)')
    parser.add_argument('--output-dir', help='Output directory for test results (default: tests/output)')
    
    # Parse remaining args
    args = parser.parse_args(sys.argv[2:])
    
    # Determine output directory
    if args.output_dir:
        output_dir = Path(args.output_dir)
    else:
        # Use tests/output relative to the tests directory
        output_dir = tests_dir / "output"
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Create and run test runner
    runner = MarkryptTestRunner(output_dir)
    
    print(f"🧪 Markrypt Test Suite")
    print(f"📁 Output directory: {output_dir}")
    print(f"🎯 Test level: {args.level}")
    print()
    
    # Run tests based on level
    if args.level == 'quick':
        result = runner.run_quick_tests()
    elif args.level == 'standard':
        result = runner.run_standard_tests()
    elif args.level == 'comprehensive':
        result = runner.run_comprehensive_tests()
    elif args.level == 'performance':
        runner.run_performance_tests()
        return
    
    # Overall summary
    success_rate = result['success_rate']
    if success_rate == 1.0:
        print(f"\n🎉 All tests passed! ({result['passed']}/{result['total_tests']})")
        sys.exit(0)
    elif success_rate >= 0.8:
        print(f"\n✅ Most tests passed ({result['passed']}/{result['total_tests']}) - {success_rate:.1%}")
        sys.exit(0)
    else:
        print(f"\n⚠️  Some tests failed ({result['passed']}/{result['total_tests']}) - {success_rate:.1%}")
        sys.exit(1)


def main():
    """Main CLI entry point that routes to encrypt, decrypt, or test"""
    parser = argparse.ArgumentParser(
        prog="markrypt",
        description="Markrypt - Markov-based text obfuscation and encryption",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  encrypt    Encrypt text with Markov-based noise insertion
  decrypt    Decrypt Markrypt-encrypted text
  test       Run Markrypt test suite
  
Examples:
  markrypt encrypt "Hello World" --key mykey
  markrypt decrypt "v1:..." --key mykey
  markrypt test --level quick
  markrypt test --level comprehensive --output-dir ./my-test-results
  
  # Get command-specific help:
  markrypt encrypt --help
  markrypt decrypt --help
  markrypt test --help
  
  # Use dedicated tools:
  markrypt-encrypt "Hello World" --key mykey --analyze
  markrypt-decrypt "v1:..." --key mykey --check-key
        """
    )
    
    parser.add_argument("command", choices=["encrypt", "decrypt", "test"], help="Operation to perform")
    parser.add_argument("args", nargs=argparse.REMAINDER, help="Arguments for the command")
    
    # Parse only the command first
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "encrypt":
        # Replace 'markrypt encrypt' with 'markrypt-encrypt' in argv
        sys.argv = ['markrypt-encrypt'] + sys.argv[2:]
        encrypt_main()
    elif command == "decrypt":
        # Replace 'markrypt decrypt' with 'markrypt-decrypt' in argv
        sys.argv = ['markrypt-decrypt'] + sys.argv[2:]
        decrypt_main()
    elif command == "test":
        run_tests()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()