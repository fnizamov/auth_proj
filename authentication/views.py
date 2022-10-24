from ast import For
from multiprocessing import context
from rest_framework.views import APIView
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated

from .serializers import (
    UserRegistrationSerializer, 
    ActivationSerializer,
    LoginSerializer,
    PasswordChangeSerializer,
    ForgottenPasswordSerializer,
    SetNewPasswordSerializer
    )

class RegistrationView(APIView):
    def post(self, request: Request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                data='Спасибо за регистрацию! На указанный адрес электронной почты был отправлен код для активации учетной записи.',
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AccountActivationView(APIView):
    def post(self, request: Request):
        serializer = ActivationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.activate_account()
            return Response(
                'Активация прошла успешно!',
                status=status.HTTP_200_OK
            )


class LoginView(ObtainAuthToken):
    serializer_class = LoginSerializer


class LogoutView(APIView):
    permission_classes = [IsAuthenticated] # позволяет получать доступ к этой вьюшке только залогиненным пользователям.

    def delete(self, request: Request):
        user = request.user
        Token.objects.filter(user=user).delete()
        return Response(
            'Вы вышли из учетной записи. До свидания!',
            status=status.HTTP_200_OK
        )


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request: Request):
        serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
        if serializer.is_valid(raise_exception=True):
            serializer.set_new_password()
            return Response(
                'Пароль успешно изменен.',
                status=status.HTTP_200_OK
                )


class ChangeForgottenPasswordView(APIView):
    def post(self, request: Request):
        serializer = ForgottenPasswordSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.send_code()
            return Response(
                'На вашу почту был выслан код для восстановления пароля'
            )


class ChangeForgottenPasswordCompleteView(APIView):
    def post(self, request: Request):
        serializer = SetNewPasswordSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.set_new_password()
            return Response(
                'Пароль успешно восстановлен',
                status=status.HTTP_200_OK
            )