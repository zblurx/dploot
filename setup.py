from setuptools import setup

setup(
    name="dploot",
    version="2.0.0",
    author="zblurx",
    author_email="seigneuret.thomas@pm.me",
    description="DPAPI looting remotely in Python",
    long_description="README.md",
    long_description_content_type="text/markdown",
    url="https://github.com/zblurx/dploot",
    license="MIT",
    install_requires=[
        "impacket",
        "cryptography>=3.5",
        "pyasn"
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
