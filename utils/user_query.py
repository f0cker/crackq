import sys

from crackq.models import User

user = User.query.filter_by(username=sys.argv[1]).first()
print(user)
