""" Set up script """
from setuptools import setup, find_packages

REQUIREMENTS = [
    "requests==2.9.1",
    "recordclass==0.5",
    "lxml==4.2.3",
]


setup(
    name="compal",
    version="0.0.1",
    author="Ties de Kock",
    author_email="ties@tiesdekock.nl",
    description=("Compal CH7465LG/Ziggo Connect Box client"),
    license="MIT",
    keywords="compal CH7465LG connect box cablemodem",
    packages=find_packages(exclude=['examples', 'tests', 'tests.*']),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Topic :: Software Development :: Libraries",
        "License :: OSI Approved :: MIT License",
    ],
    install_requires=REQUIREMENTS
)
