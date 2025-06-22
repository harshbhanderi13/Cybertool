from setuptools import setup

setup(
    name='Cybertool',
    version='1.0',
    scripts=['main.py'],
    install_requires=[
        'requests',
        'colorama',
        'nmap',
        'whois',
    ],
)
