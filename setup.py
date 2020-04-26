from setuptools import setup

setup(
    name='CMon',
    version='1.0.0',
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
