from setuptools import setup
from os import path

this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), 'rb') as f:
    long_description = f.read()

setup(name='pwnsandbox',
      version='0.3',
      description='Yet another pwn sandbox in CTF!',
      classifiers=[
          "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
          'Programming Language :: Python :: 2.7',
      ],
      keywords='pwn sandbox ctf',
      url='https://github.com/unamer/PwnSandboxForCTF',
      author='unamer',
      author_email='n0nick@protonmail.com',
      license='GPLv3',
      packages=['sandbox'],
      entry_points={
          'console_scripts': ['pwn_sandbox=sandbox.sandbox:main'],
      },
      install_requires=[
        'argparse', 'pwntools'
      ],
      include_package_data=True,
      long_description=long_description,
      long_description_content_type='text/markdown',
      zip_safe=False)
