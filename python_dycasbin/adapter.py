import hashlib

import boto3
from casbin import persist


class Adapter(persist.Adapter):
    """the interface for Casbin adapters."""

    def __init__(self, table_name='casbin_rule', **kwargs):
        """create connection and dynamodb table"""
        self.table_name = table_name
        self.dynamodb = boto3.client('dynamodb', **kwargs)
        self.dynamodb_resource = boto3.resource('dynamodb', **kwargs)

        try:

            self.dynamodb.create_table(
                TableName=self.table_name,

                AttributeDefinitions=[
                    {
                        'AttributeName': 'id',
                        'AttributeType': 'S'
                    }
                ],
                KeySchema=[
                    {
                        'AttributeName': 'id',
                        'KeyType': 'HASH'
                    },
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 10,
                    'WriteCapacityUnits': 10
                }
            )
        except self.dynamodb.exceptions.ResourceInUseException:
            pass

    def update_policy(self, sec, ptype, old_rule, new_rule):
        self.add_policy(sec, ptype, new_rule)
        self.remove_policy(sec, ptype, old_rule)
        return True

    def get_filtered_item(self, ptype,  rules):
        exp_attr = {}
        exp_attr[':ptype'] = {'S': ptype}
        filter_exp = []
        filter_exp.append('ptype = :ptype')

        for i, rule in enumerate(rules):
            exp_attr[':v{}'.format(i)] = {'S': rule}
            filter_exp.append('v{} = :v{}'.format(i, i))

        filter_exp = ' and '.join(filter_exp)

        response = self.dynamodb.scan(
            ExpressionAttributeValues=exp_attr,
            FilterExpression=filter_exp,
            TableName=self.table_name,
        )

        data = response['Items']

        while 'LastEvaluatedKey' in response:
            response = self.dynamodb.scan(
                ExclusiveStartKey=response['LastEvaluatedKey'])
            data.extend(response['Items'])

        return data

    def load_policy(self, model):
        """load all policies from database"""
        response = self.dynamodb.scan(TableName=self.table_name)

        for i in response['Items']:
            persist.load_policy_line(self.get_line_from_item(i), model)

        while 'LastEvaluatedKey' in response:
            response = self.dynamodb.scan(
                TableName=self.table_name,
                ExclusiveStartKey=response['LastEvaluatedKey'])

            for i in response['Items']:
                persist.load_policy_line(self.get_line_from_item(i), model)

            # To forcefully break the loop when testing
            if "LastEvaluatedKey" in response and response["LastEvaluatedKey"] == "from_pytest":
                break

    def get_line_from_item(self, item):
        """make casbin policy string from dynamodb item"""
        line = item['ptype']['S']
        i = 0

        while i < len(item) - 2:
            line = '{}, {}'.format(line, item['v{}'.format(i)]['S'])
            i = i + 1

        return line

    def get_md5(self, line):
        """convert policy line to MD5 hash to be used as "id" """
        m = hashlib.md5()
        m.update(str(line).encode('utf-8'))
        return m.hexdigest()

    def convert_to_item(self, ptype, rule):
        """change casbin policy string to dynamodb item"""
        line = {}
        line['ptype'] = {}
        line['ptype']['S'] = ptype

        for i, v in enumerate(rule):
            line['v{}'.format(i)] = {}
            line['v{}'.format(i)]['S'] = v

        line['id'] = {}
        line['id']['S'] = self.get_md5(line)

        return line

    def _save_policy_line(self, ptype, rule):
        """save a policy line in the dynamodb"""
        line = self.convert_to_item(ptype, rule)
        self.dynamodb.put_item(TableName=self.table_name, Item=line)

    def save_policy(self, model):
        """saves all policy rules to the storage."""
        for sec in ["p", "g"]:
            if sec not in model.model.keys():
                continue
            for ptype, ast in model.model[sec].items():
                for rule in ast.policy:
                    self._save_policy_line(ptype, rule)
        return True

    def add_policy(self, sec, ptype, rule):
        """adds a policy rule to the storage."""
        self._save_policy_line(ptype, rule)

    def remove_policy(self, sec, ptype, rule):
        """removes a policy rule from the storage."""
        line = self.convert_to_item(ptype, rule)

        _id = line['id']['S']

        self.dynamodb.delete_item(
            Key={
                'id': {
                    'S': _id,
                }
            },
            TableName=self.table_name,
        )

        return True

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """removes policy rules that match the filter from the storage.
        This is part of the Auto-Save feature.
        """
        if not (0 <= field_index <= 5):
            return False
        if not (1 <= field_index + len(field_values) <= 6):
            return False

        matched_rules = self.get_filtered_item(ptype, list(field_values))
        table = self.dynamodb_resource.Table(self.table_name)

        with table.batch_writer() as batch:
            for each in matched_rules:
                batch.delete_item(
                    Key={
                        'id': each['id']['S'],
                    }
                )

        return True
