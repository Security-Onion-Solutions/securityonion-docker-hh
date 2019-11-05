from flask import Flask, render_template
from flask_wtf import FlaskForm
from wtforms import StringField

class DefaultForm(FlaskForm):
   testfield = StringField('teststring', default="this is the default")
