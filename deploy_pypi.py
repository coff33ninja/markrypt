#!/usr/bin/env python3
"""
PyPI Deployment Script for Markrypt 2.3+

This script helps prepare and deploy Markrypt to PyPI with proper checks and validation.
Includes testing for post-quantum cryptography and steganography features.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path


def run_command(cmd, description):
    """Run a command and handle errors"""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed:")
        print(f"Error: {e.stderr}")
        return None


def check_prerequisites():
    """Check if required tools are installed"""
    print("🔍 Checking prerequisites...")
    
    tools = ['python', 'pip', 'twine']
    missing = []
    
    for tool in tools:
        # Use 'where' on Windows, 'which' on Unix
        cmd = f"where {tool}" if os.name == 'nt' else f"which {tool}"
        result = subprocess.run(cmd, shell=True, capture_output=True)
        if result.returncode != 0:
            missing.append(tool)
    
    if missing:
        print(f"❌ Missing tools: {', '.join(missing)}")
        print("Please install missing tools and try again.")
        return False
    
    print("✅ All prerequisites found")
    return True


def clean_build_artifacts():
    """Clean previous build artifacts"""
    print("🧹 Cleaning build artifacts...")
    
    dirs_to_clean = ['build', 'dist', 'markrypt.egg-info']
    for dir_name in dirs_to_clean:
        if os.path.exists(dir_name):
            shutil.rmtree(dir_name)
            print(f"  Removed {dir_name}/")
    
    print("✅ Build artifacts cleaned")


def run_tests():
    """Run the test suite"""
    print("🧪 Running test suite...")
    
    # Try to run tests using the CLI
    result = run_command("python -m markrypt test --level standard", "Test suite")
    if result is None:
        print("⚠️  Tests failed or not available. Continuing anyway...")
        return False
    
    return True


def validate_package():
    """Validate package structure and metadata"""
    print("📋 Validating package structure...")
    
    required_files = [
        'setup.py',
        'README.md',
        'CHANGELOG.md',
        'MANIFEST.in',
        'markrypt/__init__.py',
        'markrypt/core.py',
        'markrypt/pqc.py',
        'markrypt/steganography.py',
        'examples.py'
    ]
    
    missing_files = []
    for file_path in required_files:
        if not os.path.exists(file_path):
            missing_files.append(file_path)
    
    if missing_files:
        print(f"❌ Missing required files: {', '.join(missing_files)}")
        return False
    
    # Test basic import
    try:
        import markrypt
        print(f"✅ Package imports successfully (version {markrypt.__version__})")
        
        # Test core functionality
        mk = markrypt.Markrypt()
        test_msg = "Test message"
        encrypted = mk.encrypt(test_msg, mapping_key="test")
        decrypted = mk.decrypt(encrypted, mapping_key="test")
        
        if test_msg == decrypted:
            print("✅ Core encryption/decryption works")
        else:
            print("❌ Core functionality test failed")
            return False
            
    except ImportError as e:
        print(f"❌ Package import failed: {e}")
        return False
    
    print("✅ Package structure validated")
    return True


def build_package():
    """Build the package"""
    print("📦 Building package...")
    
    # Build source distribution
    if not run_command("python setup.py sdist", "Source distribution build"):
        return False
    
    # Build wheel distribution
    if not run_command("python setup.py bdist_wheel", "Wheel distribution build"):
        return False
    
    return True


def check_package():
    """Check package with twine"""
    print("🔍 Checking package with twine...")
    
    return run_command("twine check dist/*", "Package check") is not None


def upload_to_test_pypi():
    """Upload to Test PyPI"""
    print("🚀 Uploading to Test PyPI...")
    
    cmd = "twine upload --repository testpypi dist/*"
    print(f"Running: {cmd}")
    print("You'll need to enter your Test PyPI credentials.")
    
    result = subprocess.run(cmd, shell=True)
    return result.returncode == 0


def upload_to_pypi():
    """Upload to PyPI"""
    print("🚀 Uploading to PyPI...")
    
    cmd = "twine upload dist/*"
    print(f"Running: {cmd}")
    print("You'll need to enter your PyPI credentials.")
    
    result = subprocess.run(cmd, shell=True)
    return result.returncode == 0


def test_optional_features():
    """Test optional features availability"""
    print("🔮 Testing optional features...")
    
    # Test PQC
    try:
        import markrypt
        mk_pqc = markrypt.Markrypt(enable_pqc=True)
        print("✅ Post-quantum cryptography available")
    except Exception as e:
        print(f"⚠️ PQC not available: {e}")
    
    # Test Steganography
    try:
        import markrypt
        mk_stego = markrypt.Markrypt(enable_steganography=True)
        print("✅ Steganography available")
    except Exception as e:
        print(f"⚠️ Steganography not available: {e}")
    
    # Test ChaCha20
    try:
        import markrypt
        mk_chacha = markrypt.Markrypt(cipher_mode='chacha20')
        test_msg = "ChaCha20 test"
        encrypted = mk_chacha.encrypt(test_msg, mapping_key="test")
        decrypted = mk_chacha.decrypt(encrypted, mapping_key="test")
        if test_msg == decrypted:
            print("✅ ChaCha20 encryption works")
        else:
            print("⚠️ ChaCha20 test failed")
    except Exception as e:
        print(f"⚠️ ChaCha20 not available: {e}")


def run_examples():
    """Run examples to verify functionality"""
    print("📋 Running examples...")
    
    if os.path.exists("examples.py"):
        result = run_command("python examples.py", "Examples execution")
        if result is not None:
            print("✅ Examples ran successfully!")
        else:
            print("⚠️ Some examples failed (expected if optional dependencies missing)")
    else:
        print("⚠️ No examples.py found")


def main():
    """Main deployment workflow"""
    print("🎉 Markrypt 2.3+ PyPI Deployment")
    print("=" * 45)
    
    # Check prerequisites
    if not check_prerequisites():
        sys.exit(1)
    
    # Clean previous builds
    clean_build_artifacts()
    
    # Validate package
    if not validate_package():
        sys.exit(1)
    
    # Test optional features
    test_optional_features()
    
    # Run examples
    run_examples()
    
    # Run tests (optional)
    run_tests()
    
    # Build package
    if not build_package():
        print("❌ Package build failed")
        sys.exit(1)
    
    # Check package
    if not check_package():
        print("❌ Package check failed")
        sys.exit(1)
    
    print("\n📦 Package built successfully!")
    print("Contents of dist/:")
    for file in os.listdir('dist'):
        print(f"  {file}")
    
    # Ask user what to do next
    print("\nWhat would you like to do next?")
    print("1. Upload to Test PyPI (recommended first)")
    print("2. Upload to PyPI (production)")
    print("3. Exit (just build)")
    
    choice = input("Enter choice (1-3): ").strip()
    
    if choice == '1':
        if upload_to_test_pypi():
            print("✅ Successfully uploaded to Test PyPI!")
            print("Test installation with: pip install -i https://test.pypi.org/simple/ markrypt")
            print("\nTest with optional features:")
            print("pip install -i https://test.pypi.org/simple/ markrypt[full]")
        else:
            print("❌ Upload to Test PyPI failed")
    elif choice == '2':
        confirm = input("Are you sure you want to upload to production PyPI? (yes/no): ")
        if confirm.lower() == 'yes':
            if upload_to_pypi():
                print("✅ Successfully uploaded to PyPI!")
                print("Install with: pip install markrypt")
                print("\nInstallation options:")
                print("pip install markrypt[full]    # All features")
                print("pip install markrypt[pqc]     # Post-quantum crypto")
                print("pip install markrypt[stego]   # Steganography")
                print("pip install markrypt[crypto]  # Enhanced encryption")
            else:
                print("❌ Upload to PyPI failed")
        else:
            print("Upload cancelled")
    else:
        print("Build completed. Upload manually when ready.")
    
    print("\n🎊 Deployment process completed!")
    print("\n🎯 New Features in this version:")
    print("• 🔮 Post-Quantum Cryptography (Kyber + Dilithium)")
    print("• 🖼️ Steganography (hide messages in images)")
    print("• 🛡️ Hybrid security combining multiple techniques")
    print("• 💻 Enhanced CLI with new commands")
    print("• 📚 Comprehensive documentation and examples")


if __name__ == "__main__":
    main()