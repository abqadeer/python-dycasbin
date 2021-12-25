DynamoDB adopter for casbin

Installation
------------
Run `pip install python-dycasbin`

Usage
-----
```python
import casbin
from python_dycasbin import adapter

adapter = adapter.Adapter(table_name='casbin_rule', endpoint_url='http://localhost:8000')
e = casbin.Enforcer("model.conf", adapter, True)

sub = "eve4"  # the user that wants to access a resource.
obj = "data3"  # the resource that is going to be accessed.
act = "read"  # the operation that the user performs on the resource.

if e.enforce(sub, obj, act):
    print("Allow")
else:
    print("Deny")
```

Running tests
---------------
* Install [pytest](https://pypi.org/project/pytest/) and [pytest-mock](https://pypi.org/project/pytest-mock/)
* Run `pytest` from project root