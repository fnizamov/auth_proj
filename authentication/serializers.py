from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from django.core.mail import send_mail
from django.conf import settings


User = get_user_model()

class UserRegistrationSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=100, required=True)
    email = serializers.EmailField(max_length=200, required=True)
    password = serializers.CharField(max_length=128, required=True)
    password_confirm = serializers.CharField(max_length=128, required=True)

    def validate_username(self, username):
        if User.objects.filter(username=username).exists():
            raise serializers.ValidationError(
                'Пользователь с таким именем существует, выберите другое имя пользователя.'
            )
        return username

    def validate_email(self, email):
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError(
                'Указанный e-mail уже занят, укажите другой адрес эл. почты.'
            )
        return email

    def validate(self, attrs: dict):
        print('*' * 20, attrs)
        password = attrs.get('password')
        password_confirmation = attrs.pop('password_confirm')
        if password != password_confirmation:
            raise serializers.ValidationError(
                'Указанные пароли не совпадают.'
            )
        return attrs

    def create(self, validated_data: dict):
        user = User.objects.create_user(**validated_data)
        user.create_activation_code()
        user.send_activation_code()
        return user


class ActivationSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    code = serializers.CharField(min_length=1, max_length=10, required=True)

    def validate_email(self, email):
        if User.objects.filter(email=email).exists():
            return email
        raise serializers.ValidationError('Пользователь не найден')

    def validate_code(self, code):
        if not User.objects.filter(activation_code=code).exists():
            raise serializers.ValidationError('Указан неверный код')
        return code

    def validate(self, attrs: dict):
        email = attrs.get('email')
        code = attrs.get('code')
        if not User.objects.filter(email=email, activation_code=code).exists():
            raise serializers.ValidationError('Пользователь не найден')
        return attrs

    def activate_account(self):
        email = self.validated_data.get('email')
        user = User.objects.get(email=email)
        user.is_active = True
        user.activation_code = ''
        user.save()

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=100)
    password = serializers.CharField(max_length=128)


    def validate_username(self, username):
        if not User.objects.filter(username=username).exists():
            raise serializers.ValidationError(
                'Пользователя с указанным именем не существует'
            )
        return username

    def validate(self, attrs):
        print('*'*20, self.context)
        request = self.context.get('request')
        username = attrs.get('username')
        password = attrs.get('password')
        if username and password:
            user = authenticate(
                username=username,
                password=password,
                request=request
            )
            if not user:
                raise serializers.ValidationError('Неправильный логин или пароль')
        else:
            raise serializers.ValidationError('Заполните все необходимые поля')
        attrs['user'] = user
        return attrs


class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=128, required=True)
    new_password = serializers.CharField(max_length=128, required=True)
    new_password_confirm = serializers.CharField(max_length=128, required=True)

    def validate_old_password(self, old_password):
        user = self.context.get('request').user
        if not user.check_password(old_password):
            raise serializers.ValidationError('Введен неверный пароль.')
        return old_password

    def validate(self, attrs: dict):
        password = attrs.get('new_password')
        password_confirmation = attrs.get('new_password_confirm')
        if password != password_confirmation:
            raise serializers.ValidationError(
                'Указанные пароли не совпадают.'
            )
        return attrs

    def set_new_password(self):
        user = self.context.get('request').user
        password = self.validated_data.get('new_password')
        user.set_password(password)
        user.save()


class ForgottenPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True, max_length=200)

    def validate_email(self, email):
        if not User.objects.filter(email=email).exists():
            raise serializers.ValidationError(
                'Пользователя с указанной почтой не существует.'
            )
        return email

    def send_code(self):
        email = self.validated_data.get('email')
        user = User.objects.get(email=email)
        user.create_activation_code()
        send_mail(
            'Восстановление пароля',
            f'Ваш код для смены пароля: {user.activation_code}',
            settings.EMAIL_HOST_USER,
            [email]
        )


class SetNewPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    code = serializers.CharField(min_length=1, max_length=10, required=True)
    new_password = serializers.CharField(max_length=128, required=True)
    new_password_confirm = serializers.CharField(max_length=128, required=True)

    def validate_email(self, email):
        if not User.objects.filter(email=email).exists():
            raise serializers.ValidationError(
                'Пользователя с указанной почтой не существует.'
                )
        return email

    def validate_code(self, code):
        if not User.objects.filter(activation_code=code).exists():
            raise serializers.ValidationError('Указан неверный код')
        return code

    def validate(self, attrs):
        new_password = attrs.get('new_password')
        pass_confirm = attrs.get('new_password_confirm')
        if new_password != pass_confirm:
            raise serializers.ValidationError(
                'Указанные пароли не совпадают.'
            )
        return attrs

    def set_new_password(self):
        email = self.validated_data.get('email')
        user = User.objects.get(email=email)
        new_pass = self.validated_data.get('new_password')
        user.set_password(new_pass)
        user.activation_code = ''
        user.save()