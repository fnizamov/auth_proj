from django.urls import URLPattern, path
from .views import (
    AccountActivationView, 
    RegistrationView, 
    LoginView, 
    LogoutView, 
    ChangePasswordView,
    ChangeForgottenPasswordView,
    ChangeForgottenPasswordCompleteView
    )

urlpatterns = [
    path('registration/', RegistrationView.as_view(), name='register-account'),
    path('activate-account/', AccountActivationView.as_view(), name='account-activation'),
    path('login/', LoginView.as_view(), name='log-in'),
    path('logout/', LogoutView.as_view(), name='log-out'),
    path('change-password/', ChangePasswordView.as_view(), name='change-pass'),
    path('forgot-password/', ChangeForgottenPasswordView.as_view(), name='forgot-pass'),
    path('set-forgot-password/', ChangeForgottenPasswordCompleteView.as_view(), name='set-forgot-pass'),
]