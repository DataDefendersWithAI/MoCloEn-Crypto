from casbin import Enforcer, Model
import uuid
import datetime

class Person:
    def __init__(self, role: str, name: str):
        self.role = role
        self.name = name
        self.accounts = []

    def add_account(self, account: 'Account'):
        self.accounts.append(account)

    def __str__(self):
        return f"Role: {self.role}, Name: {self.name}"

    def __repr__(self):
        return self.__str__()


class Account:
    def __init__(self, name: str, owner: str):
        self.account_name = name
        self.owner = owner
        self.balance = 0
        self.account_id = str(uuid.uuid4())
        self.transactions = []

    def deposit(self, amount: float) -> bool:
        self.balance += amount
        return True

    def withdraw(self, amount: float) -> bool:
        if self.balance < amount:
            return False  # Insufficient Balance
        self.balance -= amount
        return True

    def add_transaction(self, transaction: 'Transaction'):
        self.transactions.append(transaction)

    def __str__(self):
        return f"Account ID: {self.account_id}, Account Name: {self.account_name}, Owner: {self.owner}, Balance: {self.balance}"

    def __repr__(self):
        return self.__str__()


class Transaction:
    def __init__(self, account_id: str, amount: float, transaction_type: str):
        self.transaction_id = str(uuid.uuid4())
        self.account_id = account_id
        self.amount = amount
        self.transaction_type = transaction_type
        self.timestamp = datetime.datetime.now().isoformat()

    def __str__(self):
        return f"Transaction ID: {self.transaction_id}, Account ID: {self.account_id}, Amount: {self.amount}, Type: {self.transaction_type}, Timestamp: {self.timestamp}"

    def __repr__(self):
        return self.__str__()


def verify_access(person: Person, account: Account, action: str) -> bool:
    model_text = """
    [request_definition]
    r = sub, obj, act

    [policy_definition]
    p = sub, obj, act

    [policy_effect]
    e = some(where (p.eft == allow))

    [matchers]
    m = (r.sub.role == 'user' && r.sub.name == r.obj.owner && r.act in ('create', 'deposit', 'withdraw', 'view')) || (r.sub.role == 'Admin' && r.act == 'view')
    """

    model = Model()
    model.load_model_from_text(model_text)
    e = Enforcer(model)
    return e.enforce(person, account, action)
