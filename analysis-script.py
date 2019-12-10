from database import db_session
from models import Account, SpellCheck

# looks at all accounts in accounts database
users = db_session.execute("SELECT * FROM accounts;")

# looks at all queries in spell_check database
spells = db_session.execute("SELECT * FROM spell_check;")

# looks at all queries in logs database
logs = db_session.execute("SELECT * FROM logs;")

[print(u) for u in users]
[print(s) for s in spells]
[print(l) for l in logs]