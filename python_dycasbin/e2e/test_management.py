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


def test_add_policy_get_policy():

    policy = ['ham', 'data4', 'write']
    e.add_policy(*policy)

    policies = e.get_policy()

    assert policies == [policy]


def test_enforcer():

    result_true = e.enforce('ham', 'data4', 'write')

    result_false = e.enforce('ham', 'data5', 'write')

    assert result_true == True
    assert result_false == False


def test_enforce_ex():
    result_true = e.enforce_ex('ham', 'data4', 'write')
    result_false = e.enforce_ex('ham', 'data5', 'write')

    assert result_true == (True, ['ham', 'data4', 'write'])
    assert result_false == (False, [])


def test_get_all_subjects():

    e.add_policy('alice', 'data5', 'read')

    result = e.get_all_subjects()

    assert result == ['ham', 'alice']


def test_get_all_named_subjects():

    result = e.get_all_named_subjects('p')

    assert result == ['ham', 'alice']


def test_get_all_objects():

    e.add_policy('alice', 'data5', 'read')

    result = e.get_all_objects()

    assert result == ['data4', 'data5']


def test_get_all_named_objects():

    result = e.get_all_named_objects('p')

    assert result == ['data4', 'data5']

    e.get_all_objects


def test_get_all_actions():
    result = e.get_all_actions()

    assert result == ['write', 'read']


def test_get_all_named_actions():
    result = e.get_all_named_actions('p')

    assert result == ['write', 'read']


def test_add_role_for_user():
    result = e.add_role_for_user('bob', 'admin')

    assert result == True


def test_get_all_roles():
    result = e.get_all_roles()

    assert result == ['admin']


def test_get_all_named_roles():
    result = e.get_all_named_roles('g')

    assert result == ['admin']


def test_get_filtered_policy():
    result = e.get_filtered_policy(0, 'alice')
    assert result == [['alice', 'data5', 'read']]


def test_get_named_policy():
    result = e.get_named_policy('p')
    assert result == [['ham', 'data4', 'write'], ['alice', 'data5', 'read']]


def test_get_filtered_named_policy():
    result = e.get_filtered_named_policy('p', 0, 'ham')
    assert result == [['ham', 'data4', 'write']]


def test_get_grouping_policy():
    result = e.get_grouping_policy()
    assert result == [['bob', 'admin']]


def test_get_filtered_grouping_policy():
    result = e.get_filtered_grouping_policy(0, 'bob')
    assert result == [['bob', 'admin']]


def test_get_named_grouping_policy():
    result = e.get_named_grouping_policy('g')
    assert result == [['bob', 'admin']]


def test_get_named_grouping_policy():
    result = e.get_filtered_named_grouping_policy('g', 0, 'bob')
    assert result == [['bob', 'admin']]


def test_has_policy():
    result = e.has_policy('ham', 'data4', 'write')
    assert result == True
    result = e.has_policy('ham', 'data4', 'read')
    assert result == False


def test_has_named_policy():
    result = e.has_named_policy('p', 'ham', 'data4', 'write')
    assert result == True
    result = e.has_policy('p', 'ham', 'data4', 'read')
    assert result == False


def test_add_named_policy():
    name_policy = e.add_named_grouping_policy('g', 'ham', 'data_g', 'read')
    assert name_policy == True


def test_remove_policy():
    result = e.remove_policy('ham', 'data4', 'write')
    assert result == True
    result = e.get_policy()
    assert result == [['alice', 'data5', 'read']]


def test_remove_policies():
    # Not implemented
    result = e.remove_policies('ham')
    assert result == False


def test_remove_filtered_policy():
    result = e.remove_filtered_policy(0, 'alice', 'data5', 'read')
    assert result == True
    result = e.get_policy()
    assert result == []


def test_remove_named_policy():
    r = e.add_named_policy('p', 'david', 'files', 'read')
    result = e.remove_named_policy('p', 'david', 'files', 'read')
    assert result == True
    result = e.get_policy()
    assert result == []


def test_remove_policies():
    # Not implemented
    result = e.remove_named_policies('p', 'ham')
    assert result == False


def test_remove_filtered_named_policy():
    r = e.add_named_policy('p', 'david', 'images', 'write')
    result = e.remove_filtered_named_policy('p', 0, 'david', 'images', 'write')
    assert result == True
    result = e.get_policy()
    assert result == []


def test_has_grouping_policy():
    result = e.has_grouping_policy('bob', 'admin')
    assert result == True
    result = e.has_grouping_policy('bob', 'admin2')
    assert result == False


def test_has_named_grouping_policy():
    result = e.has_named_grouping_policy('g', 'bob', 'admin')
    assert result == True
    result = e.has_named_grouping_policy('g', 'bob', 'admin2')
    assert result == False


def test_add_grouping_policy():
    result = e.add_grouping_policy('group1', 'data2_admin')
    assert result == True
    result = e.has_grouping_policy('group1', 'data2_admin')
    assert result == True


def test_add_grouping_policies():
    # Not implemented
    result = e.add_grouping_policies([
        ['ham', 'data4_admin'],
        ['jack', 'data5_admin']
    ])
    assert result == False


def test_remove_grouping_policy():
    # Not implemented
    result = e.remove_grouping_policy('group1', 'data2_admin')
    assert result == True
    result = e.has_grouping_policy('group1', 'data2_admin')
    assert result == False


def test_remove_grouping_policies():
    # Not implemented
    e.add_grouping_policy('group1', 'data2_admin')
    result = e.remove_grouping_policies([
        ['group1', 'data2_admin']
    ])
    assert result == False


def test_remove_filtered_grouping_policy():
    result = e.remove_filtered_grouping_policy(0, 'group1')
    assert result == []


def test_remove_named_grouping_policy():
    pass


def test_remove_named_grouping_policies():
    result = e.remove_named_grouping_policies('g', [
        ['ham', 'data4_admin'],
        ['jack', 'data5_admin']
    ])

    assert result == False


def test_remove_named_grouping_policy():
    e.add_grouping_policy('group1', 'data2_admin')
    result = e.remove_filtered_named_grouping_policy('g', 0, 'group1')

    assert result == [['group1', 'data2_admin']]


def test_update_policy():
    result = e.add_policy('sam', 'files', 'read')
    result = e.get_policy()
    assert result == [['sam', 'files', 'read']]
    result = e.update_policy(['sam', 'files', 'read'], ['sam', 'files', 'write'])
    assert result == True


def test_update_policies():
    # not implemented
    result = e.update_policies(['sam', 'files', 'read'], [
                               'sam', 'files', 'write'])
    assert result == False
