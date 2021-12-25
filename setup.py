import setuptools
with open("README.md", "r") as fh:
    long_description = fh.read()
setuptools.setup(
    name='python_dycasbin',
    version='0.3.1',
    author="Abdul Qadeer",
    author_email="abqdr.is@gmail.com",
    description="DynamoDB adopter for casbin",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/abqadeer/python-dynacasbin",
    keywords=["casbin" "dynamodb", "aws", "boto3", "casbin-adapter",
              "rbac", "access control", "abac", "acl", "permission"],
    install_requires=['casbin>=0.8.4', "boto3>=1.4.0"],
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
         "License :: OSI Approved :: MIT License",
         "Operating System :: OS Independent",
    ],
)
