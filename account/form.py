from django import forms
from django.contrib.auth.models import User


class LoginForm(forms.Form):
	username = forms.CharField(label='账号', required=True)
	password = forms.CharField(label='密码', widget=forms.PasswordInput,required=True)


class RegisterForm(forms.ModelForm):
	password = forms.CharField(label='密码', widget=forms.PasswordInput, required=True)
	password2 = forms.CharField(label='确认密码', widget=forms.PasswordInput, required=True)

	class Meta:
		model = User
		fields = ['username', 'email']
		labels = {'username':'账号', 'email':'邮箱'}

	# def clean_password2(self):
	# 	cd = self.cleaned_data
	# 	if cd['password'] != cd['password2']:
	# 		raise forms.ValidationError('Passwords don\'t match.')
	# 	return cd['password2']


class ChangePasswordForm(forms.Form):
	password = forms.CharField(label='当前密码', widget=forms.PasswordInput, required=True)
	password1 = forms.CharField(label='新密码', widget=forms.PasswordInput, required=True)
	password2 = forms.CharField(label='确认密码', widget=forms.PasswordInput, required=True)