import boto3
from python_dycasbin import adapter
from casbin.model.model import Model
import casbin
import python_dycasbin


table_name = 'casbin_rule'
endpoint_url = 'http://localhost:8000'
policy_line = 'mock,policy,line'


def test_init(mocker):
    mocker.patch("boto3.client")

    obj = adapter.Adapter(endpoint_url=endpoint_url)

    assert obj.table_name == table_name

    boto3.client.assert_called_with(
        'dynamodb', endpoint_url=endpoint_url)

    boto3.client.return_value.create_table.assert_called_with(
        AttributeDefinitions=[
            {'AttributeName': 'id', 'AttributeType': 'S'}],
        KeySchema=[
            {'AttributeName': 'id', 'KeyType': 'HASH'}],
        ProvisionedThroughput={
            'ReadCapacityUnits': 10, 'WriteCapacityUnits': 10},
        TableName='casbin_rule'
    )


def test_load_policy(mocker, monkeypatch):
    model = Model()
    mocker.patch("boto3.client")
    mocker.patch("casbin.persist.load_policy_line")
    monkeypatch.setattr(adapter.Adapter, "get_line_from_item",
                        mock_get_line_from_item)

    boto3.client.return_value.scan.return_value = {"Items": [{}]}

    obj = adapter.Adapter()
    obj.load_policy(model)

    boto3.client.return_value.scan.assert_called_with(TableName=table_name)
    casbin.persist.load_policy_line.assert_called_with(policy_line, model)


def test_load_polic_with_LastEvaluatedKey(mocker, monkeypatch):
    last_evaluated_key = "from_pytest"
    model = Model()
    mocker.patch("boto3.client")
    mocker.patch("casbin.persist.load_policy_line")
    monkeypatch.setattr(adapter.Adapter, "get_line_from_item",
                        mock_get_line_from_item)

    boto3.client.return_value.scan.return_value = {
        "Items": [{}], "LastEvaluatedKey": last_evaluated_key}

    obj = adapter.Adapter()
    obj.load_policy(model)

    boto3.client.return_value.scan.assert_called_with(
        TableName=table_name, ExclusiveStartKey=last_evaluated_key)
    casbin.persist.load_policy_line.assert_called_with(policy_line, model)


def test_get_line_from_item(mocker):
    mocker.patch("boto3.client")

    obj = adapter.Adapter()
    result = obj.get_line_from_item(
        {"id": "rand_id", "ptype": {"S": "p"}, "v0": {"S": "user1"}})
    assert result == 'p, user1'


def mock_get_line_from_item(itme, model):
    return policy_line
