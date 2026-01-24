from setuptools import setup, find_packages

setup(
    name="quorra-siem",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'flask>=2.3.3',
        'flask-sqlalchemy>=3.0.5',
        'flask-cors>=4.0.0',
        'requests>=2.31.0',
        'websocket-client>=1.6.3',
        'werkzeug>=2.3.7',
    ],
    entry_points={
        'console_scripts': [
            'quorra=quorra:main',
        ],
    },
    author="Security Team",
    description="SIEM tool for Block Fortress application",
    keywords="siem security monitoring block-fortress",
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Topic :: Security',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
)