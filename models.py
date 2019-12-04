from sqlalchemy import Table, Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from database import Base

class Account(Base):
	__tablename__ = 'accounts'
	username = Column(String, nullable=False, primary_key=True)
	password = Column(String, nullable=False)
	two_factor_auth = Column(Integer, nullable=False)

	def __init__(self, username, password, two_factor_auth):
		self.username = username
		self.password = password
		self.two_factor_auth = two_factor_auth
 
class SpellCheck(Base):
	__tablename__ = 'spell_check'
	spell_check_id = Column(Integer, primary_key=True)
	account_username = Column(String, ForeignKey('accounts.username'), nullable=False)
	account = relationship("Account", foreign_keys=[account_username])
	submitted_text = Column(String, nullable=True)
	result = Column(String, nullable=True)

	def __init__(self, account_username, submitted_text, result):
		self.account_username = account_username
		self.submitted_text = submitted_text
		self.result = result
 
class Log(Base):
	__tablename__ = 'logs'
	log_history_id = Column(Integer, primary_key=True)
	account_username = Column(String, ForeignKey('accounts.username'), nullable=False)
	account = relationship("Account", foreign_keys=[account_username])
	login_time = Column(String, nullable=True)
	logout_time = Column(String, nullable=True)

	def __init__(self, account_username, login_time, logout_time):
		self.account_username = account_username
		self.login_time = login_time
		self.logout_time = logout_time
