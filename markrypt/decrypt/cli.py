"""
Command-line interface for Markrypt decryption
"""

import argparse
import json
import sys
import getpass
from .decryptor import MarkryptDecryptor
from .utils import analyze_encrypted_structure, check_key_strength, detect_corruption, suggest_decryption_options
from ..exceptions import DecryptionError


def main():
    """Main CLI entry point for decryption"""
    parser = argparse.ArgumentParser(
        prog="markrypt-decrypt",
        description="Markrypt Decrypt - Markov-based text decryption",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  markrypt-decrypt "v1:..." --key mykey
  markrypt-decrypt --input-file encrypted.txt --key mykey --analyze
  markrypt-decrypt "v1:..." --key mykey --check-key
  markrypt-decrypt --batch encrypted_messages.json --output-file results.json
  
  # Via main CLI:
  markrypt decrypt "v1:..." --key mykey
        """
    )
    
    parser.add_argument("encrypted_message", nargs="?", help="Encrypted message to decrypt (or use --input-file)")
    parser.add_argument("--key", help="Decryption key")
    parser.add_argument("--no-integrity", action="store_false", dest="verify_integrity", help="Skip integrity verification")
    parser.add_argument("--input-file", help="Input file for encrypted message")
    parser.add_argument("--output-file", help="Output file for decrypted result")
    parser.add_argument("--no-encrypt-metadata", action="store_false", dest="encrypt_metadata", help="Metadata not encrypted")
    parser.add_argument("--analyze", action="store_true", help="Analyze encrypted message structure")
    parser.add_argument("--check-key", action="store_true", help="Analyze key strength")
    parser.add_argument("--batch", help="Batch decrypt from JSON file")
    parser.add_argument("--verify-only", action="store_true", help="Only verify integrity, don't decrypt")
    parser.add_argument("--quick", action="store_true", help="Quick decryption with minimal verification")
    parser.add_argument("--safe", action="store_true", help="Safe decryption with full error handling")
    parser.add_argument("--detect-corruption", action="store_true", help="Check for message corruption")
    parser.add_argument("--suggest", action="store_true", help="Get decryption suggestions")
    
    args = parser.parse_args()
    
    try:
        # Handle batch processing
        if args.batch:
            with open(args.batch, 'r', encoding='utf-8') as f:
                batch_data = json.load(f)
            
            key = args.key or getpass.getpass("Enter decryption key: ")
            
            decryptor = MarkryptDecryptor()
            result = decryptor.batch_decrypt(
                batch_data.get('encrypted_messages', []),
                key=key,
                verify_integrity=args.verify_integrity,
                encrypt_metadata=args.encrypt_metadata
            )
            
            if args.output_file:
                with open(args.output_file, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2)
                print(f"Batch results written to {args.output_file}")
            else:
                print(json.dumps(result, indent=2))
            return
        
        # Read encrypted message from file or argument
        if args.input_file:
            with open(args.input_file, 'r', encoding='utf-8') as f:
                encrypted_message = f.read().strip()
        elif args.encrypted_message:
            encrypted_message = args.encrypted_message
        else:
            encrypted_message = input("Enter encrypted message: ")
        
        if not encrypted_message:
            print("Error: No encrypted message provided")
            sys.exit(1)
        
        # Detect corruption if requested
        if args.detect_corruption:
            corruption = detect_corruption(encrypted_message)
            print("Corruption Analysis:")
            print(f"  Corrupted: {corruption['corrupted']}")
            print(f"  Confidence: {corruption['confidence']}")
            if corruption['issues']:
                print("  Issues found:")
                for issue in corruption['issues']:
                    print(f"    - {issue}")
            print()
        
        # Analyze encrypted message if requested
        if args.analyze:
            analysis = analyze_encrypted_structure(encrypted_message)
            print("Encrypted Message Analysis:")
            if analysis['format_valid']:
                for key, value in analysis.items():
                    if key != 'format_valid':
                        if isinstance(value, dict):
                            print(f"  {key}:")
                            for k, v in value.items():
                                print(f"    {k}: {v}")
                        else:
                            print(f"  {key}: {value}")
            else:
                print(f"  Error: {analysis['error']}")
            print()
        
        # Get suggestions if requested
        if args.suggest:
            suggestions = suggest_decryption_options(encrypted_message)
            print("Decryption Suggestions:")
            if 'error' not in suggestions:
                print("Recommended options:")
                for key, value in suggestions['suggestions'].items():
                    print(f"  --{key.replace('_', '-')}: {value}")
            else:
                print(f"  Error: {suggestions['error']}")
            print()
        
        # Get decryption key
        key = args.key or getpass.getpass("Enter decryption key: ")
        
        if not key:
            print("Error: Decryption key is required")
            sys.exit(1)
        
        # Check key strength if requested
        if args.check_key:
            key_analysis = check_key_strength(key)
            print("Key Strength Analysis:")
            print(f"  Strength: {key_analysis['strength']}")
            print(f"  Score: {key_analysis['score']}/{key_analysis['max_score']}")
            print("  Character types:")
            for char_type, present in key_analysis['character_types'].items():
                print(f"    {char_type}: {'✓' if present else '✗'}")
            if key_analysis['feedback']:
                print("  Recommendations:")
                for feedback in key_analysis['feedback']:
                    print(f"    - {feedback}")
            print()
        
        # Create decryptor
        decryptor = MarkryptDecryptor()
        
        # Verify integrity only if requested
        if args.verify_only:
            is_valid = decryptor.verify_integrity_only(encrypted_message, key)
            print(f"Integrity check: {'PASSED' if is_valid else 'FAILED'}")
            return
        
        # Decrypt message based on mode
        if args.safe:
            result = decryptor.safe_decrypt(encrypted_message, key)
            if result['success']:
                decrypted_text = result['decrypted']
                print("Safe decryption successful!")
                if result['warnings']:
                    print("Warnings:")
                    for warning in result['warnings']:
                        print(f"  - {warning}")
            else:
                print(f"Safe decryption failed: {result['error']}")
                sys.exit(1)
        elif args.quick:
            decrypted_text = decryptor.quick_decrypt(encrypted_message, key)
        elif args.analyze:
            result = decryptor.decrypt_with_analysis(
                encrypted_message,
                key=key,
                verify_integrity=args.verify_integrity,
                encrypt_metadata=args.encrypt_metadata
            )
            
            print("Decryption Analysis:")
            for key_name, value in result['analysis'].items():
                print(f"  {key_name}: {value}")
            print()
            
            decrypted_text = result['decrypted']
        else:
            decrypted_text = decryptor.decrypt_text(
                encrypted_message,
                key=key,
                verify_integrity=args.verify_integrity,
                encrypt_metadata=args.encrypt_metadata
            )
        
        # Output result
        if args.output_file:
            with open(args.output_file, 'w', encoding='utf-8') as f:
                f.write(decrypted_text)
            print(f"Decrypted result written to {args.output_file}")
        else:
            print(f"Decrypted: {decrypted_text}")
    
    except DecryptionError as e:
        print(f"Decryption error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()