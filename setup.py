from setuptools import setup

from src.cmon import __version__

setup(
    name='CMon',
    version=__version__,
    license='Apache 2.0',
    author='David Nugent',
    author_email='davidn@uniquode.io',
    description='Continuous connection monitoring and logging tool',
    scripts=[
        'src/cmon.py'
    ],
    url='',
    install_requires=[
        'scapy'
    ]
)
