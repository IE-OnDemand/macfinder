# Always prefer setuptools over distutils
from setuptools import setup
#from setuptools import setup, find_packages
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()


setup(
    name='macfinder',
    version='0.1.2',
    description='Parser library for Wireshark\'s OUI database',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/IE-OnDemand/macfinder',
    author='Ricky Laney',
    author_email='rlaney@ineteng.com',
    license = 'Apache License 2.0 or GPLv3',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.8'
    ],
    keywords = ['manuf', 'mac address', 'networking'],
    include_package_data=True,
    packages = ['src'],
    entry_points={
        'console_scripts': [
            'macfinder=src.macfinder:main'
        ],
    },
    package_data = {
        'src': ['manuf']
    },
)
# To publish package run:
# $ rm -rf dist #Delete all previous build that you might not want to upload
# $ python setup.py build check sdist bdist_wheel #Build
# $ twine upload --verbose dist/* #Upload
