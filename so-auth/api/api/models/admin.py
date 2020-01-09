from api.models import DB


class Admin(DB.Model):
    created: bool = DB.Column(DB.Boolean, primary_key=True)
    first_run: bool = DB.Column(DB.Boolean)

    def __init__(self):
        self.created = True
        self.first_run = True
