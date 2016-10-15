from setuptools import setup


requirements = [
    'aniso8601>=1.0.0',
    'requests>=2.6.2'
]

setup(
    name="pyarkosclient",
    version="0.3",
    description="Python bindings for remote management of arkOS servers via their Kraken REST API",
    url='https://arkos.io',
    author='Jacob Cook',
    author_email='jacob@citizenweb.io',
    license='GPLv3',
    classifiers=[
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: Unix"
    ],
    packages=['pyarkosclient'],
    install_requires=requirements
)
