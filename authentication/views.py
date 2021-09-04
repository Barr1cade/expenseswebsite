from django.shortcuts import render, redirect
from django.views import View
import json
from django.http import JsonResponse
from django.contrib.auth.models import User
import json
from django.http import JsonResponse
from django.contrib.auth.models import User
from validate_email import validate_email
from django.contrib import messages
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text, DjangoUnicodeDecodeError
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.template.loader import render_to_string
from .utils import token_generator
from django.urls import reverse
from django.contrib import auth
from django.contrib.auth.tokens import PasswordResetTokenGenerator


# from django.core.validators import validate_email


# Create your views here.
class EmailValidationView(View):
    def post(self, request):
        data = json.loads(request.body)
        email = data['email']
        if not validate_email(email):
            return JsonResponse({'email_error': 'Email is invalid.'}, status=400)
        if User.objects.filter(email=email).exists():
            return JsonResponse({'email_error': 'Sorry, current email already has been taken.'
                                                'Choose another one.'}, status=409)
        return JsonResponse({'email_valid': True})


class UsernameValidationView(View):
    def post(self, request):
        data = json.loads(request.body)
        username = data['username']
        if not str(username).isalnum():
            return JsonResponse({'username_error': 'A username should contain only alphanumeric.'},
                                status=400)
        if User.objects.filter(username=username).exists():
            return JsonResponse({'username_error': 'Sorry, username already has been taken.'
                                                   'Choose another one.'}, status=409)

        return JsonResponse({'username_valid': True})


class RegistrationView(View):
    def get(self, request):
        return render(request, 'authentication/register.html')

    def post(self, request):
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']

        context = {
            'fieldValues': request.POST
        }

        if not User.objects.filter(username=username).exists():
            if not User.objects.filter(email=email).exists():
                if len(password) < 6:
                    messages.error(request, 'The password is too short.')
                    return render(request, 'authentication/register.html', context)

                user = User.objects.create_user(username=username, email=email)
                user.set_password(password)
                user.is_active = False
                user.save()
                current_site = get_current_site(request)
                email_body = {
                    'user': user,
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': token_generator.make_token(user),
                }

                link = reverse('activate', kwargs={
                    'uidb64': email_body['uid'], 'token': email_body['token']})

                email_subject = 'Activate your account'

                activate_url = 'http://' + current_site.domain + link
                # uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
                #
                # domain = get_current_site(request).domain  # pythonanywhere.com...
                # link = reverse('activate', kwargs={
                #     'uidb64': uidb64, 'token': token_generator.make_token(user)})
                #
                # activate_url = 'http://' + domain + link
                #
                # email_body = 'Hi, ' + user.username + \
                #              '!\nPlease use this link to verify your account\n' + activate_url
                #
                # email_subject = 'Activate your account.'

                # email = EmailMessage(
                #     email_subject,
                #     email_body,
                #     'noreply@semycolon.com',
                #     [email],
                # )
                # email.send(fail_silently=False)
                email = EmailMessage(
                    email_subject,
                    'Hi ' + user.username + ', Please the link below to activate your account \n' + activate_url,
                    'noreply@semycolon.com',
                    [email],
                )
                email.send(fail_silently=False)
                messages.success(request, 'Account successfully created.')
                return render(request, 'authentication/register.html')

        return render(request, 'authentication/register.html')


class VerificationView(View):
    def get(self, request, uidb64, token):

        try:
            id = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=id)

            if not token_generator.check_token(user, token):
                return redirect('login' + '?message=' + 'User already activated.')

            if user.is_active:
                return redirect('login')
            user.is_active = True
            user.save()

            messages.success(request, 'Account activated successfully.')
            return redirect('login')

        except Exception as e:
            pass

        return redirect('login')


class LoginView(View):
    def get(self, request):
        return render(request, 'authentication/login.html')

    def post(self, request):
        username = request.POST['username']
        password = request.POST['password']

        if username and password:
            user = auth.authenticate(username=username, password=password)

            if user:
                if user.is_active:
                    auth.login(request, user)
                    messages.success(request, 'Welcome, ' +
                                     user.username + '! You are now logged in.')
                    return redirect('expenses')

                messages.error(request, 'Account is not active. Check your e-mail please.')
                return render(request, 'authentication/login.html')
            messages.error(request, 'Invalid credentials. Try again.')
            return render(request, 'authentication/login.html')

        messages.error(request, 'Fill all fields please.')
        return render(request, 'authentication/login.html')


class LogoutView(View):
    def post(self, request):
        auth.logout(request)
        messages.success(request, 'You have been logged out.')
        return redirect('login')


class RequestPasswordResetEmail(View):
    def get(self, request):
        return render(request, 'authentication/reset-password.html')

    def post(self, request):
        email = request.POST['email']

        context = {
            'values': request.POST
        }

        if not validate_email(email):
            messages.error(request, 'Please provide a valid e-mail.')
            return render(request, 'authentication/reset-password.html', context)

        current_site = get_current_site(request)

        user = User.objects.filter(email=email)
        if user.exists():
            email_contents = {
                'user': user[0],
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user[0].pk)),
                'token': PasswordResetTokenGenerator().make_token(user[0]),
            }

            link = reverse('reset-user-password', kwargs={
                'uidb64': email_contents['uid'], 'token': email_contents['token']})

            email_subject = 'Password reset instructions.'

            reset_url = 'http://' + current_site.domain + link
            email = EmailMessage(
                email_subject,
                'Hi there! Please click the link below to reset your password \n' + reset_url,
                'noreply@semycolon.com',
                [email],
            )
            email.send(fail_silently=False)
        messages.success(request, 'We have sent you an email to reset your password.')

        return render(request, 'authentication/reset-password.html')


class CompletePasswordReset(View):
    def get(self, request, uidb64, token):

        context = {
            'uidb64': uidb64,
            'token': token
        }

        try:
            user_id = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                messages.info(request, 'Password link is invalid. Please request a new one.')
                return render(request, 'authentication/reset-password.html')
            return render(request, 'authentication/set-new-password.html', context)

        except Exception as identifier:
            messages.info(request, 'Something went wrong, try again.')
            return render(request, 'authentication/reset-password.html')

    def post(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token
        }
        password = request.POST['password']
        password2 = request.POST['password2']
        if password != password2:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'authentication/set-new-password.html', context)

        if len(password) < 6:
            messages.error(request, 'The password is too short.')
            return render(request, 'authentication/set-new-password.html', context)

        try:
            user_id = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)
            user.set_password(password)
            user.save()

            messages.success(request, 'Password reset successful.')
            return redirect('login')
        except Exception as identifier:
            messages.info(request, 'Something went wrong, try again.')
            return render(request, 'authentication/set-new-password.html', context)
