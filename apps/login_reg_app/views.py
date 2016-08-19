from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib import messages
from models import User

def index(request):
    return render(request, 'login_reg_app/index.html')

def register(request):
    result = User.objects.validateReg(request)
    if result[0] == False:
        print_messages(request, result[1])
        return redirect(reverse('index'))
    return log_user_in(request, result[1])

def login(request):
    result = User.objects.validateLogin(request)
    if result[0] == False:
        print_messages(request, result[1])
        return redirect(reverse('index'))
    return log_user_in(request, result[1])

def log_user_in(request, user):
    request.session['user'] = {
        'id' : user.id,
        'first_name' : user.first_name,
        'last_name' : user.last_name,
        'email' : user.email,
    }
    return redirect(reverse('success'))

def success(request):
    if not 'user' in request.session:
        return redirect(reverse('index'))
    print (request.session['user'])
    return render(request, 'login_reg_app/success.html')

def print_messages(request, message_list):
    for message in message_list:
        messages.add_message(request, messages.ERROR, message)

def logout(request):
    request.session.pop('user')
    return redirect(reverse('index'))

def delete(request, user_id):
    User.objects.delete(user_id)
    return redirect('/')
