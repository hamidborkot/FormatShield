from setuptools import setup, find_packages

setup(
    name="formatshield",
    version="1.0.0",
    author="Md. Hamid Borkot Tulla",
    description="Pre-LLM structural gate against format-based prompt injection in RAG pipelines",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.10",
    install_requires=[
        "groq>=0.8.0",
        "openai>=1.12.0",
        "pandas>=2.1.0",
        "numpy>=1.26.0",
        "python-dotenv>=1.0.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
)
