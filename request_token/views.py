from email.mime import message
from django.shortcuts import render,redirect
from django.contrib.auth.models import auth,User
from django.contrib import messages
from django.http import HttpResponse
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_200_OK
)
from rest_framework.response import Response
from django.contrib.auth import logout as Logout
from django.contrib.auth.decorators import login_required

user=None
def Login(request):
    if request.user.is_authenticated:
        return HttpResponse("Logged in!!")
    else:
        if request.method == 'POST':
            username = request.POST.get('username')
            password = request.POST.get('password')
            user_check = auth.authenticate(username=username, password=password)
            if user_check is not None:
                global user
                user=user_check
                return redirect('tel-otp')
            else:
                messages.info(request,"Invalid Credentials")
                return redirect('login')
        
        else:
            return render(request, 'login.html')



def OtpVerification(request):
    if request.method == "POST":
        otp = request.POST.get('otp')
        # user = request.user
        token, _ = Token.objects.get_or_create(user=user)
        if otp=="1234":
            auth.login(request, user)
            return redirect(f'login/{token.key}')
        else:
            messages.info(request,"Incorrect OTP")
    return render(request, 'otp-verification.html')

def RequestToken(request,token):
    return HttpResponse(token)


