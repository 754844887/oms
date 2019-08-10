from django.shortcuts import render, redirect
from .form import LoginForm, RegisterForm, ChangePasswordForm
from django import forms
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import get_object_or_404
from django.http import HttpResponse
from django.contrib.auth.models import User


######################################
# 主页
######################################
def index(request):
	return render(request, 'account/index.html')


######################################
# 用户登录
######################################
def user_login(request):
	if request.method == 'POST':
		form = LoginForm(request.POST)
		if form.is_valid():
			cd = form.cleaned_data
			user = authenticate(username=cd['username'], password=cd['password'])
			if user is not None:
				if user.is_active:
					login(request, user)
					return redirect('account:index')
				else:
					message = '用户已被禁用'
			else:
				message = '用户名或密码错误'
			return render(request, 'account/login.html', {'message': message})
		else:
			message = '输入不合法'
			return render(request, 'account/login.html', {'message': message})
	else:
		form = LoginForm()
		return render(request, 'account/login.html', {'form': form})



######################################
# 用户注销
######################################
def user_logout(request):
	logout(request)
	return redirect('account:login')



######################################
# 用户注册
######################################
def user_register(request):
	if request.method == 'POST':
		form = RegisterForm(request.POST)
		if form.is_valid():
			cd = form.cleaned_data
			if cd['password'] != cd['password2']:
				message = '两次输入的密码不匹配'
				return render(request, 'account/register.html', {'message': message, 'form':form})
			new_user = form.save(commit=False)
			new_user.set_password(cd['password'])
			new_user.save()
			return render(request, 'account/register.html', {'new_user': new_user})
	else:
		form = RegisterForm()
		return render(request, 'account/register.html', {'form': form})


def change_password(request):
	if request.method == 'POST':
		form = ChangePasswordForm(request.POST)
		if form.is_valid():
			cd = form.cleaned_data
			user = authenticate(username=request.user, password=cd['password'])
			if cd['password1'] != cd['password2']:
				message = '两次输入的密码不匹配'
			elif user is None:
				message = '当前密码输入错误'
			else:
				user.set_password(cd['password1'])
				message = '密码修改成功'
			return render(request, 'account/change_password.html', {'message': message, 'form': form})
	else:
		form = ChangePasswordForm()
	return render(request, 'account/change_password.html',{'form':form})





