import os.path
from setuptools import setup

version = "0.1"

install_requires = ["pyramid", "PyJWT", "cryptography", "requests", "zope.interface"]

tests_require = ["pytest", "pytest-flake8", "requests-mock", "WebTest"]

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, "README.rst")).read()
CHANGES = open(os.path.join(here, "CHANGES.rst")).read()

setup(
    name="pyramid_iap",
    version=version,
    description="Google Cloud Identity-Aware Proxy authentication policy for Pyramid",
    long_description=README + "\n\n" + CHANGES,
    keywords='Pyramid JWT IAP authentication security',
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    author="Laurence Rowe",
    author_email="laurence@lrowe.co.uk",
    url="https://github.com/lrowe/pyramid_iap",
    license="BSD",
    packages=["pyramid_iap"],
    package_dir={"": "src"},
    include_package_data=True,
    zip_safe=True,
    install_requires=install_requires,
    tests_require=tests_require,
    extras_require={"tests": tests_require},
    setup_requires=["pytest-runner"],
)
