import casbin
import os
from python_dycasbin import adapter
import boto3


os.environ['AWS_ACCESS_KEY_ID'] = 'key'
os.environ['AWS_SECRET_ACCESS_KEY'] = 'anything'
os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'

client = boto3.client('dynamodb', endpoint_url="http://localhost:8000")
table_name = 'casbin_rule'

adapter = adapter.Adapter(endpoint_url="http://localhost:8000")
e = casbin.Enforcer("python_dycasbin/e2e/model.conf", adapter)
# e = casbin.Enforcer("python_dycasbin/e2e/model.conf", "python_dycasbin/e2e/policy.csv" )


def test_add_and_get_roles_for_user():
    e.add_role_for_user('ham', 'data_admin')
    result = e.get_roles_for_user('ham')
    assert result == ['data_admin']


def test_get_users_for_role():
    result = e.get_users_for_role('data_admin')
    assert result == ['ham']


def test_has_role_for_user():
    result = e.has_role_for_user('ham', 'data_admin')
    assert result == True
    result = e.has_role_for_user('sam', 'data_admin')
    assert result == False


def test_delete_role_for_user():
    result = e.delete_role_for_user('ham', 'data_admin')
    assert result == True


def test_delete_roles_for_user():
    e.add_role_for_user('ham', 'data_admin')
    result = e.delete_roles_for_user('ham')
    assert result == [['ham', 'data_admin']]
    result = e.has_role_for_user('ham', 'data_admin')
    assert result == False


def test_delete_user():
    e.add_role_for_user('ham', 'data_admin')
    result = e.has_role_for_user('ham', 'data_admin')
    result = e.delete_user('ham')
    assert result == [['ham', 'data_admin']]
    result = e.has_role_for_user('ham', 'data_admin')
    assert result == False


def test_delete_role():
    e.add_role_for_user('sam', 'data_admin')
    result = e.has_role_for_user('sam', 'data_admin')
    result = e.delete_role('data_admin')
    assert result == [['sam', 'data_admin']]
    result = e.has_role_for_user('sam', 'data_admin')
    assert result == False


def test_add_permission_for_user():
    e.add_permission_for_user('bob', 'read')
    result = e.has_permission_for_user('bob', 'read')
    assert result == True


def test_delete_permission():
    e.add_permission_for_user('bob', 'read')
    result = e.delete_permission('read')
    assert result == True
    result = e.has_permission_for_user('bob', 'read')
    assert result == False


def test_add_permission_for_user():
    e.add_permission_for_user('alice', 'write')
    result = e.delete_permission_for_user('alice', 'write')
    assert result == True
    result = e.has_permission_for_user('alice', 'write')
    assert result == False


def test_delete_permissions_for_user():
    e.add_permission_for_user('alice', 'write')
    e.add_permission_for_user('alice', 'read')
    result = e.delete_permissions_for_user('alice')
    assert result == True
    result = e.has_permission_for_user('alice', 'write')
    assert result == False
    result = e.has_permission_for_user('alice', 'read')
    assert result == False


def test_delete_permissions_for_user():
    e.add_permission_for_user('alice', 'write')
    e.add_permission_for_user('alice', 'read')
    result = e.get_permissions_for_user('alice')
    assert result == [['alice', 'write'], ['alice', 'read']]


def test_get_users_for_role_in_domain():
    e.add_role_for_user_in_domain('ham', 'data_admin', 'domain1')
    e.add_role_for_user_in_domain('sam', 'data2_admin', 'domain1')
    e.add_role_for_user_in_domain('alice', 'data2_admin', 'domain1')
    e.add_role_for_user_in_domain('sam', 'data2_admin', 'domain2')
    result = e.get_users_for_role_in_domain('data2_admin', 'domain1')
    result.sort()
    assert result == ['alice', 'sam']


def test_get_roles_for_user_in_domain():
    e.add_role_for_user_in_domain('alice', 'data3_admin', 'domain1')
    e.add_role_for_user_in_domain('alice', 'data2_admin', 'domain1')
    result = e.get_roles_for_user_in_domain('alice', 'domain1')
    result.sort()
    assert result == ['data2_admin', 'data3_admin']


def test_get_permissions_for_user_in_domain():
    e.add_role_for_user_in_domain('alice', 'data3_admin', 'domain1')
    e.add_role_for_user_in_domain('alice', 'data2_admin', 'domain1')
    result = e.get_permissions_for_user_in_domain('alice', 'domain1')
    assert result == []


def test_get_permissions_for_user_in_domain():
    e.delete_roles_for_user_in_domain('alice', 'data3_admin', 'domain1')
    result = e.get_roles_for_user_in_domain('alice', 'domain1')
    result.sort()
    assert result == ['data2_admin']


def test_delete_table():
    client.delete_table(
        TableName=table_name
    )
