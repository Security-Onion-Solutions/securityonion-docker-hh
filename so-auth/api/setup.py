from setuptools import setup, find_packages

setup(
    name='Security Onion Auth',
    version='0.1a',
    # long_description=__doc__,
    packages=[
        'api',
    ],
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'Flask-Cors',
        'Flask-SQLAlchemy',
        'Flask-Limiter',
        'PyJWT',
        'pyOpenSSL',
        'bcrypt',
        'Flask',
    ]
)
