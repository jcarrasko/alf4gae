
# Put here your models or extend User model from bp_includes/models.py
from google.appengine.ext import ndb

class repo(ndb.Model):
    repositoryId = ndb.KeyProperty()
    vendorName = ndb.StringProperty()
    productVersion = ndb.StringProperty()

    
    