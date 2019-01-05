from setuptools import setup

setup(name='pwnsandbox',
      version='0.1',
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
          'lief', 'argparse', 'pwntools'
      ],
      include_package_data=True,
      zip_safe=False)
