from setuptools import setup, find_packages

setup(
    name='crackq',
    author='Daniel Turner',
    version='0.0.3',
    packages=['crackq'],
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'crackq = crackq:main',
        ]
        },
      )
#packages=find_packages())
