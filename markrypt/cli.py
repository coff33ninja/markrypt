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


def run_pqc_keygen():
    """Generate post-quantum cryptography keypairs"""
    parser = argparse.ArgumentParser(
        prog="markrypt pqc-keygen",
        description="Generate post-quantum cryptography keypairs"
    )
    parser.add_argument('--type', choices=['kyber', 'dilithium'], default='kyber',
                       help='Type of keypair to generate (default: kyber)')
    parser.add_argument('--output-dir', help='Output directory for keys (default: current directory)')
    parser.add_argument('--prefix', default='markrypt', help='Prefix for key files (default: markrypt)')
    
    args = parser.parse_args(sys.argv[2:])
    
    try:
        from markrypt import Markrypt
        mk = Markrypt(enable_pqc=True)
        
        print(f"🔮 Generating {args.type} keypair...")
        keypair = mk.generate_pqc_keypair(args.type)
        
        # Determine output directory
        output_dir = Path(args.output_dir) if args.output_dir else Path.cwd()
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Write keys to files
        public_key_file = output_dir / f"{args.prefix}_{args.type}_public.key"
        secret_key_file = output_dir / f"{args.prefix}_{args.type}_secret.key"
        
        public_key_file.write_text(keypair['public_key'])
        secret_key_file.write_text(keypair['secret_key'])
        
        print(f"✅ Keypair generated successfully!")
        print(f"📁 Public key: {public_key_file}")
        print(f"🔐 Secret key: {secret_key_file}")
        print(f"⚠️  Keep the secret key safe and never share it!")
        
    except Exception as e:
        print(f"❌ Failed to generate keypair: {e}")
        print("Install PQC dependencies: pip install markrypt[pqc]")
        sys.exit(1)


def run_stego_hide():
    """Hide message in image using steganography"""
    parser = argparse.ArgumentParser(
        prog="markrypt stego-hide",
        description="Hide encrypted message in image"
    )
    parser.add_argument('message', help='Message to hide')
    parser.add_argument('--key', required=True, help='Encryption key')
    parser.add_argument('--image', required=True, help='Cover image path')
    parser.add_argument('--output', required=True, help='Output image path')
    parser.add_argument('--stego-password', help='Additional steganography password')
    parser.add_argument('--cipher-mode', choices=['substitution', 'chacha20'], 
                       default='chacha20', help='Encryption mode (default: chacha20)')
    
    args = parser.parse_args(sys.argv[2:])
    
    try:
        from markrypt import Markrypt
        mk = Markrypt(enable_steganography=True, cipher_mode=args.cipher_mode)
        
        print(f"🖼️ Hiding message in image...")
        print(f"📁 Cover image: {args.image}")
        print(f"💾 Output image: {args.output}")
        
        result = mk.encrypt_and_hide_in_image(
            args.message, args.key, args.image, args.output, 
            stego_password=args.stego_password
        )
        
        print(f"✅ Message hidden successfully!")
        print(f"📊 Capacity utilization: {result['utilization']}")
        print(f"📏 Original message: {result['original_message_length']} chars")
        print(f"🔐 Encrypted message: {result['encrypted_message_length']} chars")
        
    except Exception as e:
        print(f"❌ Failed to hide message: {e}")
        print("Install steganography dependencies: pip install markrypt[stego]")
        sys.exit(1)


def run_stego_extract():
    """Extract message from image using steganography"""
    parser = argparse.ArgumentParser(
        prog="markrypt stego-extract",
        description="Extract hidden message from image"
    )
    parser.add_argument('image', help='Image with hidden message')
    parser.add_argument('--key', required=True, help='Decryption key')
    parser.add_argument('--stego-password', help='Steganography password')
    
    args = parser.parse_args(sys.argv[2:])
    
    try:
        from markrypt import Markrypt
        mk = Markrypt(enable_steganography=True)
        
        print(f"🔍 Extracting message from image...")
        print(f"📁 Image: {args.image}")
        
        message = mk.extract_and_decrypt_from_image(
            args.image, args.key, stego_password=args.stego_password
        )
        
        print(f"✅ Message extracted successfully!")
        print(f"📝 Message: {message}")
        
    except Exception as e:
        print(f"❌ Failed to extract message: {e}")
        print("Install steganography dependencies: pip install markrypt[stego]")
        sys.exit(1)


def run_stego_analyze():
    """Analyze image for steganography capacity"""
    parser = argparse.ArgumentParser(
        prog="markrypt stego-analyze",
        description="Analyze image for steganography capacity"
    )
    parser.add_argument('image', help='Image to analyze')
    
    args = parser.parse_args(sys.argv[2:])
    
    try:
        from markrypt import Markrypt
        mk = Markrypt(enable_steganography=True)
        
        print(f"🔍 Analyzing image capacity...")
        analysis = mk.analyze_image_capacity(args.image)
        
        print(f"✅ Analysis complete!")
        print(f"📁 Image: {args.image}")
        print(f"📏 Dimensions: {analysis['dimensions']}")
        print(f"🔢 Total pixels: {analysis['total_pixels']:,}")
        print(f"💾 Capacity: {analysis['capacity_chars']:,} characters ({analysis['capacity_kb']:.1f} KB)")
        print(f"📊 File size: {analysis['file_size_bytes']:,} bytes")
        
        if analysis.get('suspected_steganography'):
            print(f"⚠️  This image may already contain hidden data")
        
    except Exception as e:
        print(f"❌ Failed to analyze image: {e}")
        print("Install steganography dependencies: pip install markrypt[stego]")
        sys.exit(1)


def main():
    """Main CLI entry point that routes to encrypt, decrypt, test, pqc, or stego commands"""
    parser = argparse.ArgumentParser(
        prog="markrypt",
        description="Markrypt - Advanced text obfuscation with post-quantum cryptography and steganography",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  encrypt       Encrypt text with Markov-based noise insertion
  decrypt       Decrypt Markrypt-encrypted text
  test          Run Markrypt test suite
  pqc-keygen    Generate post-quantum cryptography keypairs
  stego-hide    Hide encrypted message in image
  stego-extract Extract hidden message from image
  stego-analyze Analyze image steganography capacity
  
Examples:
  markrypt encrypt "Hello World" --key mykey
  markrypt decrypt "v1:..." --key mykey
  markrypt test --level quick
  markrypt pqc-keygen --type kyber --output-dir ./keys
  markrypt stego-hide "Secret message" --key mykey --image cover.png --output hidden.png
  markrypt stego-extract hidden.png --key mykey
  markrypt stego-analyze cover.png
  
  # Get command-specific help:
  markrypt encrypt --help
  markrypt pqc-keygen --help
  markrypt stego-hide --help
  
  # Use dedicated tools:
  markrypt-encrypt "Hello World" --key mykey --analyze
  markrypt-decrypt "v1:..." --key mykey --check-key
        """
    )
    
    parser.add_argument("command", choices=["encrypt", "decrypt", "test", "pqc-keygen", "stego-hide", "stego-extract", "stego-analyze"], 
                       help="Operation to perform")
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
    elif command == "pqc-keygen":
        run_pqc_keygen()
    elif command == "stego-hide":
        run_stego_hide()
    elif command == "stego-extract":
        run_stego_extract()
    elif command == "stego-analyze":
        run_stego_analyze()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()