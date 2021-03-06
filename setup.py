import subprocess
from setuptools import setup

# Lets get the version from git tag last one wins
VERSION = '1.0.0'

setup(
    name='nhltv',
    version=VERSION,
    description='Download NHL games from game center',
    url='https://github.com/cmaxwe/dl-nhltv',
    license='None',
    keywords='NHL GAMECENTER',
    packages=['nhltv_lib'],
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'nhltv=nhltv_lib.main:parse_args'],
    })
