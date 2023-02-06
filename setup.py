from setuptools import setup

setup(
    name="dploot",
    version="2.1.9",
    author="zblurx",
    author_email="seigneuret.thomas@pm.me",
    description="DPAPI looting remotely in Python",
    long_description="README.md",
    long_description_content_type="text/markdown",
    url="https://github.com/zblurx/dploot",
    license="MIT",
    install_requires=[
        "impacket>=0.10.0",
        "cryptography>=3.5",
        "pyasn1>=0.4.8",
        "lxml==4.9.2"
    ],
    python_requires='>=3.6',
    packages=[
        "dploot",
        "dploot.lib",
        "dploot.action",
        "dploot.triage",
],
    entry_points={
        "console_scripts": ["dploot=dploot.entry:main"],
    },
)
