'''
SSL/TLS service info utility

'''
from os import path
from codecs import open
from setuptools import setup


here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='tls-probe',
    version='0.0.3',
    description='probe specified SSL/TLS service and return information',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/dspruell/tls-probe',
    author='Darren Spruell',
    author_email='dspruell@sancho2k.net',
    license='ISC',
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # 'Development Status :: 3 - Alpha',
        'Development Status :: 4 - Beta',
        # 'Development Status :: 5 - Production/Stable',
        # 'Development Status :: 6 - Mature',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: System :: Networking :: Monitoring',
    ],
    py_modules=['tls_probe'],
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'cryptography',
        'tabulate',
    ],
    entry_points={
        'console_scripts': [
            'tls-probe = tls_probe:cli',
        ],
    },
)
