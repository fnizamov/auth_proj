from django.db import models
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.core.validators import validate_email
from django.conf import settings


class UserManager(BaseUserManager):
    def _create(self, username, password, email, **extra_fields):
        if not username:
            raise ValueError('User must have username')
        user = self.model(
            username=username,
            password=password,
            email=self.normalize_email(email),
            **extra_fields
            )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, username, password, email, **extra_fields):
        extra_fields.setdefault('is_active', False)
        extra_fields.setdefault('is_staff', False)
        return self._create(username, password, email, **extra_fields)

    def create_superuser(self, username, password, email, **extra_fields):
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_staff', True)
        return self._create(username, password, email, **extra_fields)



class User(AbstractBaseUser):
    username = models.CharField(max_length=100, primary_key=True)
    email = models.EmailField(max_length=200, unique=True, validators=[validate_email])
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    activation_code = models.CharField(max_length=10, blank=True)

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    objects = UserManager()

    def __str__(self):
        return self.get_username()

    def has_perm(self, obj=None):
        return self.is_staff

    def has_module_perms(self, app_label):
        return self.is_staff

    def create_activation_code(self):
        from django.utils.crypto import get_random_string
        code = get_random_string(length=10)
        if User.objects.filter(activation_code=code).exists():
            self.create_activation_code()
        self.activation_code = code
        self.save()

    def send_activation_code(self):
        from django.core.mail import send_mail
        send_mail(
            'Спасибо за регистрацию!',
            message=f'Это Ваш код для активации учетной записи {self.activation_code}',
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[self.email],
            fail_silently=False
        )