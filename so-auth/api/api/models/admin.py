from api.models import db


class Admin(db.Model):
    created: bool = db.Column(db.Boolean, primary_key=True)
    first_run: bool = db.Column(db.Boolean)

    def __init__(self):
        self.created = True
        self.first_run = True
