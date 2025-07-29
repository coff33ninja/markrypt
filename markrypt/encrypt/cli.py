"""
Command-line interface for Markrypt encryption
"""

import argparse
import json
import sys
import getpass
from .encryptor import MarkryptEncryptor
from .utils import analyze_message, suggest_options
from ..exceptions import MarkryptError


def main():
    """Main CLI entry point for encryption"""
    parser = argparse.ArgumentParser(
        prog="markrypt-encrypt",
        description="Markrypt Encrypt - Markov-based text encryption",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  markrypt-encrypt "Hello World" --key mykey
  markrypt-encrypt --input-file message.txt --key mykey --qr-file qr.png
  markrypt-encrypt "Secret" --suggest  # Get encryption suggestions
  markrypt-encrypt --batch messages.json --output-file results.json
  
  # Via main CLI:
  markrypt encrypt "Hello World" --key mykey
        """
    )
    
    parser.add_argument("message", nargs="?", help="Message to encrypt (or use --input-file)")
    parser.add_argument("--key", help="Encryption key (random if not provided)")
    parser.add_argument("--seed", type=int, help="Random seed for reproducibility")
    parser.add_argument("--no-noise", action="store_false", dest="noise", help="Disable noise insertion")
    parser.add_argument("--no-symbols", action="store_false", dest="preserve_symbols", help="Strip symbols")
    parser.add_argument("--noise-style", choices=["markov", "lowercase", "custom", "emoji"], default="markov", help="Noise style")
    parser.add_argument("--custom-noise", help="Custom noise character set")
    parser.add_argument("--noise-exclude", help="Characters to exclude from noise")
    parser.add_argument("--no-integrity", action="store_false", dest="integrity_check", help="Disable integrity check")
    parser.add_argument("--input-file", help="Input file for message")
    parser.add_argument("--output-file", help="Output file for result")
    parser.add_argument("--qr-file", help="Output file for QR code (PNG)")
    parser.add_argument("--json-output", action="store_true", help="Output result as JSON")
    parser.add_argument("--no-encrypt-metadata", action="store_false", dest="encrypt_metadata", help="Disable metadata encryption")
    parser.add_argument("--unicode-range", choices=["basic", "full"], default="basic", help="Unicode character range")
    parser.add_argument("--unicode-blocks", nargs="*", help="Specific Unicode blocks")
    parser.add_argument("--cipher-mode", choices=["substitution", "chacha20"], default="substitution", help="Encryption cipher mode")
    parser.add_argument("--analyze", action="store_true", help="Analyze message before encryption")
    parser.add_argument("--suggest", action="store_true", help="Get encryption suggestions")
    parser.add_argument("--batch", help="Batch encrypt from JSON file")
    parser.add_argument("--quick", action="store_true", help="Quick encryption with default settings")
    
    args = parser.parse_args()
    
    try:
        # Handle batch processing
        if args.batch:
            with open(args.batch, 'r', encoding='utf-8') as f:
                batch_data = json.load(f)
            
            encryptor = MarkryptEncryptor(
                seed=args.seed,
                preserve_symbols=args.preserve_symbols,
                noise=args.noise,
                noise_style=args.noise_style,
                custom_noise_chars=args.custom_noise,
                noise_exclude=args.noise_exclude,
                unicode_range=args.unicode_range,
                unicode_blocks=args.unicode_blocks,
                cipher_mode=args.cipher_mode
            )
            
            result = encryptor.batch_encrypt(
                batch_data.get('messages', []),
                key=args.key,
                integrity_check=args.integrity_check,
                json_output=args.json_output,
                encrypt_metadata=args.encrypt_metadata
            )
            
            if args.output_file:
                with open(args.output_file, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2)
                print(f"Batch results written to {args.output_file}")
            else:
                print(json.dumps(result, indent=2))
            return
        
        # Read message from file or argument
        if args.input_file:
            with open(args.input_file, 'r', encoding='utf-8') as f:
                message = f.read()
        elif args.message:
            message = args.message
        else:
            message = input("Enter message to encrypt: ")
        
        if not message:
            print("Error: No message provided")
            sys.exit(1)
        
        # Analyze message if requested
        if args.analyze:
            analysis = analyze_message(message)
            print("Message Analysis:")
            for key, value in analysis.items():
                print(f"  {key}: {value}")
            print()
        
        # Get suggestions if requested
        if args.suggest:
            suggestions = suggest_options(message)
            print("Encryption Suggestions:")
            print("Analysis:")
            for key, value in suggestions['analysis'].items():
                print(f"  {key}: {value}")
            print("\nRecommended options:")
            for key, value in suggestions['suggestions'].items():
                print(f"  --{key.replace('_', '-')}: {value}")
            print("\nReasoning:")
            for reason in suggestions['reasoning']:
                print(f"  - {reason}")
            print()
        
        # Get encryption key
        key = args.key or getpass.getpass("Enter encryption key (press Enter for random): ") or None
        
        # Create encryptor
        encryptor = MarkryptEncryptor(
            seed=args.seed,
            preserve_symbols=args.preserve_symbols,
            noise=args.noise,
            noise_style=args.noise_style,
            custom_noise_chars=args.custom_noise,
            noise_exclude=args.noise_exclude,
            unicode_range=args.unicode_range,
            unicode_blocks=args.unicode_blocks,
            cipher_mode=args.cipher_mode
        )
        
        # Encrypt message
        if args.quick:
            result = encryptor.quick_encrypt(message, key=key)
        elif args.qr_file:
            result = encryptor.encrypt_with_qr(
                message,
                key=key,
                qr_file=args.qr_file,
                integrity_check=args.integrity_check,
                json_output=args.json_output,
                encrypt_metadata=args.encrypt_metadata
            )
            print(f"QR code saved to {args.qr_file}")
        else:
            result = encryptor.encrypt_text(
                message,
                key=key,
                integrity_check=args.integrity_check,
                json_output=args.json_output,
                encrypt_metadata=args.encrypt_metadata
            )
        
        # Output result
        if args.output_file:
            with open(args.output_file, 'w', encoding='utf-8') as f:
                if args.json_output:
                    json.dump(result, f, indent=2)
                else:
                    f.write(result)
            print(f"Encrypted result written to {args.output_file}")
        else:
            if args.json_output:
                print(json.dumps(result, indent=2))
            else:
                print(f"Encrypted: {result}")
    
    except MarkryptError as e:
        print(f"Encryption error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()