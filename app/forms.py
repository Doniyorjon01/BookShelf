
from flask_wtf import FlaskForm

from wtforms.fields.numeric import FloatField
from wtforms.fields.simple import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, ValidationError, EqualTo, Email, NumberRange
from app.models import Users


class RegistrationForm(FlaskForm):
    username = StringField('username', validators=[DataRequired()])
    full_name = StringField('full_name', validators=[DataRequired()])
    # phone = StringField('Phone', validators=[DataRequired(), Length(min=13, max=13)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    # balance = FloatField('Balance', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    # confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self,username):
        user = Users.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Already exist')

    def validate_email(self,email):
        user = Users.query.filter_by(email=email.data).first()
        if user: raise ValidationError("Already exist")




class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

    def validate_email(self, email):
        user = Users.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('Invalid email')


class TransferForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    balance = FloatField('Balance', validators=[DataRequired()])
    submit = SubmitField('Transfer')

    def validate_balance(self, balance):
        if balance.data <= 0:
            raise ValidationError('Balans 0 dan katta bo\'lishi kerak.')

    def validate_username(self, username):
        recipient = Users.query.filter_by(username=username.data).first()
        if not recipient:
            raise ValidationError('Bu foydalanuvchi mavjud emas.')