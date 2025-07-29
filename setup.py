from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="markrypt",
    version="2.3.0",
    description="Advanced text obfuscation with post-quantum cryptography, steganography, ChaCha20 encryption, and Markov-based patterns",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="coff33ninja",
    author_email="coff33ninja69@gmail.com",
    url="https://github.com/coff33ninja/markrypt",
    packages=find_packages(),
    install_requires=[],
    extras_require={
        "crypto": ["cryptography"],
        "qr": ["qrcode[pil]"],
        "api": ["fastapi", "uvicorn"],
        "pqc": ["pqcrypto", "kyber-py"],
        "stego": ["Pillow", "numpy", "opencv-python"],
        "full": ["cryptography", "qrcode[pil]", "fastapi", "uvicorn", "pqcrypto", "kyber-py", "Pillow", "numpy", "opencv-python"],
    },
    entry_points={
        "console_scripts": [
            "markrypt=markrypt.cli:main",
            "markrypt-encrypt=markrypt.encrypt.cli:main",
            "markrypt-decrypt=markrypt.decrypt.cli:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
        "Topic :: Text Processing",
    ],
    keywords="encryption, obfuscation, markov, text, security, chacha20, emoji, stream-cipher, post-quantum, steganography, kyber, dilithium",
)