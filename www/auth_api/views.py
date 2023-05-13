from django.shortcuts import render

# Create your views here.
from django.conf import settings
from django.contrib.auth import logout, get_user_model
from django.contrib.auth.models import AnonymousUser, User

# Create your views here.
from django.contrib.auth.tokens import default_token_generator
from django.db import transaction
from django.http import JsonResponse, HttpResponse
from django.shortcuts import redirect, get_object_or_404
from django.utils.encoding import force_text
from django.utils.http import urlsafe_base64_decode
from django.utils.translation import ugettext_lazy as _
from rest_framework import permissions, status
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.decorators import api_view, action
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import IsAuthenticated, DjangoModelPermissions, AllowAny
from rest_framework.response import Response
from rest_framework.reverse import reverse
from rest_framework.status import HTTP_200_OK, HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet

from .serializers import UserRegisterSerializer, PasswordSerializer, LoginToken, ChangePasswordSerializer
from .tokens import account_activation_token

UserModel = get_user_model()

__all__ = [

    'Login'
]


class Login(ObtainAuthToken):
    serializer_class = LoginToken


class UserPermission(permissions.BasePermission):

    def has_permission(self, request, view):
        print(request, view.action)
        if view.action == 'list':
            return request.user.is_authenticated and request.user.is_staff
        elif view.action == 'create':
            return True
        elif view.action in ['retrieve', 'update', 'partial_update']:
            return True
        elif view.action == 'destroy' and request.user.is_staff:
            return True
        else:
            return False

    def has_object_permission(self, request, view, obj):
        # Deny actions on objects if the user is not authenticated
        print(request, view, obj)
        if not request.user.is_authenticated:
            return False

        if view.action == 'retrieve':
            return obj == request.user or request.user.is_staff
        elif view.action in ['update', 'partial_update']:
            return obj == request.user or request.user.is_staff
        elif view.action == 'destroy':
            return request.user.is_staff
        else:
            return False


class UserViewSet(ModelViewSet):
    permission_classes = [UserPermission]
    serializer_class = UserRegisterSerializer
    queryset = UserModel.objects.all()

    @transaction.atomic
    @action(detail=False, methods=['post'], permission_classes=[AllowAny])
    def register(self, request):
        """
        Registro por parte de usuario
        :param request:
        :return:
        """
        from .utils import send_email_user_activation
        data = request.data
        serializer = UserRegisterSerializer(data=data)
        if serializer.is_valid():
            user = serializer.save()
            headers = self.get_success_headers(serializer.data)
            send_email_user_activation(user=user, name=f"{user.first_name} {user.last_name}", to_email=user.email,
                                       subject=_("Verificar correo"), template_name="email/account_activate_email.html",
                                       )
            return Response(status=201, data={"msg": _("Usuario creado")}, headers=headers)
        else:
            return Response(data={'message': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post', 'put'], permission_classes=[IsAuthenticated])
    def set_password(self, request):
        """
        Cambio de contraseña desde sesion iniciada
        :param request:
        :return:
        """
        user_id = request.user.pk
        user = User.objects.get(pk=user_id)
        data = request.data
        data['user'] = user
        serializer = ChangePasswordSerializer(data=data)
        if serializer.is_valid():
            new_password = request.data['new_password']
            user.set_password(new_password)
            user.save()
            return JsonResponse({'message': _('¡La contraseña se ha cambiado con éxito!')}, status=status.HTTP_200_OK)
        else:
            return JsonResponse({'message': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['put'], permission_classes=[IsAuthenticated])
    def change_profile(self, request, *args, **kwargs):
        """
        Cambios de datos de usuario
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        instance = self.request.user
        partial = kwargs.pop('partial', False)
        serializer = self.serializer_class(instance=instance, data=request.data, partial=partial)
        if serializer.is_valid():
            instance.first_name = serializer.validated_data['first_name']
            instance.last_name = serializer.validated_data['last_name']
            # instance.email = serializer.validated_data['email']
            instance.save()
            return JsonResponse({'message': _('¡Sean actualizado los datos con éxito!')}, status=status.HTTP_200_OK)
        else:
            return JsonResponse({'message': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post', 'put'], permission_classes=[AllowAny])
    def request_password_reset(self, request):
        """
        Solicitud de cambio de contraseña
        :param request:
        :return:
        """
        from .utils import send_email_user_activation
        # from .utils import send_email_user_activation
        email = request.data.get('email', '')
        if email.strip():
            qs = UserModel.objects.filter(email=email)
            res = qs.exists()
            if res:
                user = qs.first()
                name = f"{user.first_name} {user.last_name}"
                try:
                    send_email_user_activation(user=user, name=name, to_email=user.email,
                                               subject="Restablecer contraseña",
                                               template_name='email/password_reset_email.html', reset_password=True,
                                               domain_frontend=True)
                    return JsonResponse({'Correo enviado': res}, status=200)
                except:
                    return JsonResponse({'error': _('Error al enviar correo')}, status=500)
            else:
                return JsonResponse({'error': _('El correo ingresado no existe')}, status=403)
        else:
            return JsonResponse({'error': _('Correo invalido')}, status=400)

    @action(methods=['get'], detail=False, permission_classes=[IsAuthenticated])
    def session(self, request):
        """
        Usuario que se encuentra en sesión
        :param request:
        :return:
        """

        return Response(status=HTTP_200_OK, data=self.serializer_class(request.user).data)

    @transaction.atomic
    @action(methods=['post'], detail=False, permission_classes=[AllowAny])
    def activate(self, request, *args, **kwargs):
        """
        Api para activar usuario
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        uidb64 = request.data.get('uidb64', False)
        token = request.data.get('token', False)
        token_check = False
        if not (uidb64 and token):
            return Response(status=403, data={"msg": _('Sin token')})
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            # user_reg = Register.objects.get(pk=uid)
            user = UserModel.objects.get(pk=uid)
            token_check = account_activation_token.check_token(user, token)
        except(TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

            # if user is not None and account_activation_token.check_token(user, token):
        if user and token_check:
            if user.is_active:

                return Response(status=200, data={"message": _("Usuario ya activo")})
            else:
                user.is_active = True
                user.save()
                user.backend = 'django.contrib.auth.backends.ModelBackend'
                return Response(status=200, data={"message": _("Usuario activado")})
                # return HttpResponse('Thank you for your email confirmation. Now you can login your account.')
        else:
            return Response(status=400)

    @transaction.atomic
    @action(methods=['post'], detail=False, permission_classes=[AllowAny])
    def password_reset(self, request):
        from django.http import JsonResponse
        uidb64 = request.data.get('uidb64', False)
        token = request.data.get('token', False)
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            # user_reg = Register.objects.get(pk=uid)
            user = UserModel.objects.get(pk=uid)
            token_check = account_activation_token.check_token(user, token)
        except(TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
            token_check = False
        # if user is not None and account_activation_token.check_token(user, token):
        if user and token_check:
            serializer = PasswordSerializer(data=request.data)
            if serializer.is_valid():
                password = request.data['new_password']
                user.set_password(password)
                user.save()
                return JsonResponse({'message': _('¡La contraseña se ha cambiado con éxito!')}, status=200,
                                    )
            return JsonResponse({'message': serializer.errors}, status=400)
            # return HttpResponse('Thank you for your email confirmation. Now you can login your account.')
        else:
            return JsonResponse({'token': False}, status=403)

    @action(methods=['post'], detail=False, permission_classes=[IsAuthenticated])
    def logout(self, request):
        """
        Cierre de sesion
        :param request:
        :return:
        """
        if isinstance(request.user, AnonymousUser):
            return Response(status=HTTP_200_OK)

        if hasattr(request.user, 'auth_token'):
            request.user.auth_token.delete()

        logout(request)

        return Response(_('El usuario se desconectó con éxito'), status=HTTP_200_OK)

    @action(methods=['post'], detail=False, permission_classes=[AllowAny])
    def check_email_exist(self, request):
        """
        Chequear si existe el correo
        :param request:
        :return:
        """
        email = request.data.get('email', '')
        if email.strip():
            res = UserModel.objects.filter(email=email).exists()
        else:
            res = False
        return JsonResponse({'exists': res}, status=HTTP_200_OK)


class DjangoModelPermissionsAPI(DjangoModelPermissions):
    perms_map = {
        'GET': ['%(app_label)s.view_%(model_name)s'],
        'OPTIONS': [],
        'HEAD': [],
        'POST': ['%(app_label)s.add_%(model_name)s'],
        'PUT': ['%(app_label)s.change_%(model_name)s'],
        'PATCH': ['%(app_label)s.change_%(model_name)s'],
        'DELETE': ['%(app_label)s.delete_%(model_name)s'],
    }
